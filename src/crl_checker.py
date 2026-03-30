"""
CRL（憑證吊銷列表）檢查模組

從 CRL 發佈點下載 CRL，驗證憑證是否已被吊銷。
"""

import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import requests
except ImportError:
    raise ImportError("需要安裝: cryptography, requests")

logger = logging.getLogger(__name__)


class CRLChecker:
    """CRL 驗證檢查器"""
    
    # 請求超時設定（秒）
    TIMEOUT = 10
    
    def __init__(self):
        self.backend = default_backend()
        self.cache = {}  # CRL 快取
    
    def check_revocation(self, cert_der: bytes, crl_urls: List[str]) -> Dict[str, Any]:
        """
        檢查憑證是否在 CRL 中被吊銷
        
        參數：
            cert_der: 憑證的 DER 編碼二進位內容
            crl_urls: CRL 發佈點 URL 列表
        
        返回：
            {
                'revoked': True | False | None,
                'message': '驗證訊息',
                'checked_urls': [檢查過的 URLs],
                'error': '如果有錯誤'
            }
        """
        if not crl_urls:
            logger.warning("沒有可用的 CRL 發佈點")
            return {
                'revoked': None,
                'message': '沒有 CRL 發佈點可驗證',
                'checked_urls': [],
                'error': 'no_crl_urls'
            }
        
        try:
            cert = x509.load_der_x509_certificate(cert_der, self.backend)
            serial = cert.serial_number
            
            logger.info(f"開始檢查 CRL，序列號: {serial}")
            
            checked_urls = []
            
            # 嘗試從每個 CRL URL 檢查
            for crl_url in crl_urls:
                try:
                    logger.debug(f"從 {crl_url} 下載 CRL")
                    checked_urls.append(crl_url)
                    
                    crl_data = self._download_crl(crl_url)
                    if crl_data:
                        result = self._check_certificate_in_crl(serial, crl_data)
                        return {
                            'revoked': result,
                            'message': f"憑證{'已被吊銷' if result else '未被吊銷'}（根據 CRL）",
                            'checked_urls': checked_urls,
                            'crl_url_used': crl_url
                        }
                
                except Exception as e:
                    logger.warning(f"CRL 檢查失敗 ({crl_url}): {e}")
                    continue
            
            # 所有 CRL URL 都失敗
            return {
                'revoked': None,
                'message': '無法驗證 CRL（所有發佈點都不可用）',
                'checked_urls': checked_urls,
                'error': 'all_urls_failed'
            }
            
        except Exception as e:
            logger.error(f"CRL 驗證過程出錯: {e}")
            return {
                'revoked': None,
                'message': f"CRL 驗證出錯: {str(e)}",
                'checked_urls': checked_urls if 'checked_urls' in locals() else [],
                'error': 'check_error'
            }
    
    def _download_crl(self, url: str) -> Optional[bytes]:
        """
        從 URL 下載 CRL
        
        參數：
            url: CRL URL（通常為 HTTP/HTTPS）
        
        返回：
            CRL 的二進位內容，或 None 如果下載失敗
        """
        # 快取檢查
        if url in self.cache:
            logger.debug(f"使用快取的 CRL: {url}")
            return self.cache[url]
        
        try:
            logger.debug(f"下載 CRL: {url}")
            response = requests.get(url, timeout=self.TIMEOUT, verify=True)
            response.raise_for_status()
            
            crl_data = response.content
            
            # 快取 CRL
            self.cache[url] = crl_data
            logger.info(f"CRL 下載成功: {url}")
            
            return crl_data
            
        except requests.RequestException as e:
            logger.error(f"CRL 下載失敗: {e}")
            return None
        except Exception as e:
            logger.error(f"CRL 下載過程出錯: {e}")
            return None
    
    def _check_certificate_in_crl(self, serial_number: int, crl_data: bytes) -> bool:
        """
        檢查序列號是否在 CRL 中
        
        參數：
            serial_number: 憑證序列號
            crl_data: CRL 的二進位內容
        
        返回：
            True 如果序列號在 CRL 中（已吊銷），False 否則
        """
        try:
            crl = x509.load_der_x509_crl(crl_data, self.backend)
            
            # 檢查每一個已吊銷的憑證
            revoked_certs = crl.revoked_certificates
            if revoked_certs:
                for revoked_cert in revoked_certs:
                    if revoked_cert.serial_number == serial_number:
                        logger.warning(f"憑證已被吊銷（CRL）: {serial_number}")
                        return True
            
            logger.debug(f"憑證未在 CRL 中被吊銷: {serial_number}")
            return False
            
        except Exception as e:
            logger.error(f"CRL 檢查失敗: {e}")
            raise
