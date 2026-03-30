"""
憑證檢查模組

從網址獲取 SSL/TLS 憑證並解析關鍵資訊。
"""

import ssl
import socket
import logging
from datetime import datetime
from typing import Dict, Any, Tuple
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    from cryptography.hazmat.backends import default_backend
except ImportError:
    raise ImportError("需要安裝 cryptography 套件: pip install cryptography")

logger = logging.getLogger(__name__)


class CertificateChecker:
    """從網址獲取並解析 SSL 憑證"""
    
    # 連線超時設定（秒）
    SOCKET_TIMEOUT = 10
    
    def __init__(self):
        self.backend = default_backend()
    
    def get_certificate(self, hostname: str, port: int = 443) -> bytes:
        """
        從網址獲取 SSL 憑證（DER 格式）
        
        參數：
            hostname: 網址（如 google.com）
            port: 連接連接埠（預設 443）
        
        返回：
            憑證的 DER 編碼二進位內容
        
        拋出：
            Exception: 連接失敗或憑證獲取失敗
        """
        try:
            # 使用 Python 內建 ssl 模組取得憑證
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.SOCKET_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    
            if not cert_der:
                raise ValueError(f"無法從 {hostname} 取得憑證")
            
            logger.info(f"成功從 {hostname} 獲取憑證")
            return cert_der
            
        except ssl.SSLError as e:
            logger.error(f"SSL 錯誤 ({hostname}): {e}")
            raise
        except Exception as e:
            logger.error(f"憑證獲取失敗 ({hostname}): {e}")
            raise
    
    def parse_certificate(self, cert_der: bytes) -> Dict[str, Any]:
        """
        解析 DER 格式憑證，提取關鍵資訊
        
        參數：
            cert_der: 憑證的 DER 編碼二進位內容
        
        返回：
            包含憑證資訊的字典：
            {
                'subject': '憑證主體 (CN)',
                'issuer': '發行者',
                'not_before': datetime 物件,
                'not_after': datetime 物件,
                'serial_number': '序列號',
                'crl_distribution_points': [CRL URLs],
                'ocsp_url': 'OCSP 回應器 URL',
                'public_key_info': 'RSA/ECDSA 等'
            }
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der, self.backend)
            
            # 提取主題（Subject）- CN（Common Name）
            subject = None
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    subject = attr.value
                    break
            
            # 提取發行者（Issuer）
            issuer = None
            for attr in cert.issuer:
                if attr.oid == NameOID.COMMON_NAME:
                    issuer = attr.value
                    break
            
            # 使用 UTC 欄位，避免 cryptography 的 naive datetime 棄用警告。
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            
            # 提取序列號
            serial_number = format(cert.serial_number, 'x')
            
            # 提取 CRL 發佈點
            crl_urls = []
            try:
                crl_dist = cert.extensions.get_extension_for_oid(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS
                )
                for point in crl_dist.value:
                    if point.full_name:
                        for name in point.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                crl_urls.append(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # 提取 OCSP URL
            ocsp_url = None
            try:
                aia = cert.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                for desc in aia.value:
                    if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                        if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                            ocsp_url = desc.access_location.value
                            break
            except x509.ExtensionNotFound:
                pass
            
            # 提取公鑰類型
            public_key = cert.public_key()
            key_type = type(public_key).__name__
            
            result = {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'serial_number': serial_number,
                'crl_distribution_points': crl_urls,
                'ocsp_url': ocsp_url,
                'public_key_type': key_type,
                'certificate_der': cert_der
            }
            
            logger.debug(f"憑證解析成功: {subject}")
            return result
            
        except Exception as e:
            logger.error(f"憑證解析失敗: {e}")
            raise
    
    def is_expired(self, cert_info: Dict[str, Any]) -> bool:
        """
        檢查憑證是否已過期
        
        參數：
            cert_info: 由 parse_certificate() 返回的憑證資訊
        
        返回：
            True 如果已過期，False 如果仍有效
        """
        now = datetime.now(cert_info['not_after'].tzinfo)
        not_after = cert_info['not_after']
        
        is_exp = now > not_after
        logger.debug(f"憑證過期檢查: {cert_info['subject']} -> {'已過期' if is_exp else '有效'}")
        
        return is_exp
    
    def days_until_expiry(self, cert_info: Dict[str, Any]) -> int:
        """
        計算憑證距離過期還有多少天
        
        參數：
            cert_info: 由 parse_certificate() 返回的憑證資訊
        
        返回：
            天數（負數表示已過期）
        """
        now = datetime.now(cert_info['not_after'].tzinfo)
        not_after = cert_info['not_after']
        
        delta = not_after - now
        days = delta.days
        
        logger.debug(f"憑證有效期: {cert_info['subject']} -> {days} 天")
        
        return days
