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

from network_utils import (
    RetryExhaustedError,
    build_retry_policy,
    execute_with_retry,
    format_exception_message,
    is_retryable_requests_exception,
)

logger = logging.getLogger(__name__)


class CRLChecker:
    """CRL 驗證檢查器"""

    def __init__(self, network_config: Optional[Dict[str, Any]] = None):
        self.backend = default_backend()
        self.cache = {}  # CRL 快取
        self.retry_policy = build_retry_policy(network_config)
    
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
            checked_url_details = []
            
            # 嘗試從每個 CRL URL 檢查
            for crl_url in crl_urls:
                try:
                    logger.debug(f"從 {crl_url} 下載 CRL")
                    checked_urls.append(crl_url)
                    
                    download_result = self._download_crl(crl_url)
                    if not download_result or not download_result.get('crl_data'):
                        checked_url_details.append({
                            'url': crl_url,
                            'status': 'failed',
                            'attempts_used': download_result.get('attempts_used', 0) if download_result else 0,
                            'retries_used': download_result.get('retries_used', 0) if download_result else 0,
                            'error': download_result.get('error', 'download_failed') if download_result else 'download_failed'
                        })
                        continue

                    crl_data = download_result.get('crl_data')
                    if crl_data:
                        result = self._check_certificate_in_crl(serial, crl_data)
                        checked_url_details.append({
                            'url': crl_url,
                            'status': 'succeeded',
                            'attempts_used': download_result['attempts_used'],
                            'retries_used': download_result['retries_used'],
                        })
                        return {
                            'revoked': result,
                            'message': f"憑證{'已被吊銷' if result else '未被吊銷'}（根據 CRL）",
                            'checked_urls': checked_urls,
                            'checked_url_details': checked_url_details,
                            'crl_url_used': crl_url,
                            'attempts_used': download_result['attempts_used'],
                            'retries_used': download_result['retries_used']
                        }
                
                except Exception as e:
                    logger.warning(f"CRL 檢查失敗 ({crl_url}): {e}")
                    checked_url_details.append({
                        'url': crl_url,
                        'status': 'failed',
                        'attempts_used': 0,
                        'retries_used': 0,
                        'error': str(e)
                    })
                    continue
            
            # 所有 CRL URL 都失敗
            return {
                'revoked': None,
                'message': '無法驗證 CRL（所有發佈點都不可用）',
                'checked_urls': checked_urls,
                'checked_url_details': checked_url_details,
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
    
    def _download_crl(self, url: str) -> Optional[Dict[str, Any]]:
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
            return {
                'crl_data': self.cache[url],
                'attempts_used': 1,
                'retries_used': 0,
                'source': 'cache'
            }
        
        try:
            logger.debug(f"下載 CRL: {url}")

            def _fetch_response() -> bytes:
                response = requests.get(
                    url,
                    timeout=self.retry_policy.timeout_seconds,
                    verify=True,
                )
                response.raise_for_status()
                return response.content

            retry_result = execute_with_retry(
                operation_name="CRL 下載",
                target=url,
                func=_fetch_response,
                policy=self.retry_policy,
                logger=logger,
                retryable=is_retryable_requests_exception,
            )

            crl_data = retry_result.value
            
            # 快取 CRL
            self.cache[url] = crl_data
            logger.info(f"CRL 下載成功: {url}")
            
            return {
                'crl_data': crl_data,
                'attempts_used': retry_result.attempts_used,
                'retries_used': retry_result.retries_used,
                'source': 'network'
            }
            
        except RetryExhaustedError as e:
            logger.error(
                "CRL 下載失敗: url=%s, attempts_used=%s, retries_used=%s, error=%s",
                url,
                e.attempts_used,
                e.retries_used,
                format_exception_message(e.last_error),
            )
            return {
                'crl_data': None,
                'attempts_used': e.attempts_used,
                'retries_used': e.retries_used,
                'source': 'network',
                'error': format_exception_message(e.last_error)
            }
        except Exception as e:
            logger.error(f"CRL 下載過程出錯: {e}")
            return {
                'crl_data': None,
                'attempts_used': 1,
                'retries_used': 0,
                'source': 'network',
                'error': str(e)
            }
    
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

            # cryptography 新版可直接迭代 CRL 條目
            for revoked_cert in crl:
                if revoked_cert.serial_number == serial_number:
                    logger.warning(f"憑證已被吊銷（CRL）: {serial_number}")
                    return True
            
            logger.debug(f"憑證未在 CRL 中被吊銷: {serial_number}")
            return False
            
        except Exception as e:
            logger.error(f"CRL 檢查失敗: {e}")
            raise
