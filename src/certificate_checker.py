"""
憑證檢查模組

從網址獲取 SSL/TLS 憑證並解析關鍵資訊。
"""

import ssl
import socket
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    import requests
except ImportError:
    raise ImportError("需要安裝 cryptography, requests 套件")

from network_utils import (
    RetryExhaustedError,
    build_retry_policy,
    execute_with_retry,
    format_exception_message,
    is_retryable_requests_exception,
    is_retryable_socket_exception,
)

logger = logging.getLogger(__name__)


class CertificateChecker:
    """從網址獲取並解析 SSL 憑證"""

    def __init__(self, network_config: Optional[Dict[str, Any]] = None):
        self.backend = default_backend()
        self.retry_policy = build_retry_policy(network_config)

    def _extract_issuer_cert_url(self, cert: x509.Certificate) -> Optional[str]:
        """從 AIA 擴展提取 issuer certificate URL（CA Issuers）。"""
        try:
            from cryptography.x509.oid import AuthorityInformationAccessOID

            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            for desc in aia.value:
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        return desc.access_location.value
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"提取 issuer URL 失敗: {e}")

        return None

    def _download_issuer_certificate(self, issuer_url: str) -> tuple[Optional[bytes], Optional[str]]:
        """下載 issuer 憑證並標準化為 DER。"""
        try:
            def _fetch_response() -> bytes:
                response = requests.get(
                    issuer_url,
                    timeout=self.retry_policy.timeout_seconds,
                    verify=True,
                )
                response.raise_for_status()
                return response.content

            retry_result = execute_with_retry(
                operation_name="Issuer 憑證下載",
                target=issuer_url,
                func=_fetch_response,
                policy=self.retry_policy,
                logger=logger,
                retryable=is_retryable_requests_exception,
            )
            data = retry_result.value

            try:
                # 先嘗試 DER
                x509.load_der_x509_certificate(data, self.backend)
                return data, None
            except Exception:
                pass

            try:
                # 再嘗試 PEM 並轉 DER
                cert = x509.load_pem_x509_certificate(data, self.backend)
                return cert.public_bytes(serialization.Encoding.DER), None
            except Exception:
                return None, 'unsupported_issuer_certificate_format'

        except RetryExhaustedError as e:
            logger.warning(
                "下載 issuer 憑證失敗: url=%s, attempts_used=%s, retries_used=%s, error=%s",
                issuer_url,
                e.attempts_used,
                e.retries_used,
                format_exception_message(e.last_error),
            )
            return None, 'issuer_download_failed'
        except Exception as e:
            logger.warning(f"處理 issuer 憑證失敗: {e}")
            return None, 'issuer_processing_failed'

    def load_issuer_certificate_from_url(self, issuer_url: str) -> tuple[Optional[bytes], Optional[str]]:
        """由指定 URL 下載 issuer 憑證並轉換為 DER。"""
        if not issuer_url:
            return None, 'empty_issuer_url'
        return self._download_issuer_certificate(issuer_url)
    
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
            def _fetch_certificate() -> bytes:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection(
                    (hostname, port),
                    timeout=self.retry_policy.timeout_seconds,
                ) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        return ssock.getpeercert(binary_form=True)

            retry_result = execute_with_retry(
                operation_name="網站憑證連線",
                target=f"{hostname}:{port}",
                func=_fetch_certificate,
                policy=self.retry_policy,
                logger=logger,
                retryable=is_retryable_socket_exception,
            )
            cert_der = retry_result.value
                    
            if not cert_der:
                raise ValueError(f"無法從 {hostname} 取得憑證")
            
            logger.info(f"成功從 {hostname} 獲取憑證")
            return cert_der
            
        except RetryExhaustedError as e:
            logger.error(
                "憑證獲取失敗 (%s): attempts_used=%s, retries_used=%s, error=%s",
                hostname,
                e.attempts_used,
                e.retries_used,
                format_exception_message(e.last_error),
            )
            raise e.last_error
        except ssl.SSLError as e:
            logger.error(f"SSL 錯誤 ({hostname}): {e}")
            raise
        except Exception as e:
            logger.error(f"憑證獲取失敗 ({hostname}): {e}")
            raise
    
    def parse_certificate(self, cert_der: bytes, skip_aia_issuer_download: bool = False) -> Dict[str, Any]:
        """
        解析 DER 格式憑證，提取關鍵資訊
        
        參數：
            cert_der: 憑證的 DER 編碼二進位內容
            skip_aia_issuer_download: 是否略過從 AIA 自動下載 issuer 憑證（預設 False）
        
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

            # 提取並下載 issuer 憑證（供 OCSP 驗證使用）
            issuer_cert_url = self._extract_issuer_cert_url(cert)
            issuer_certificate_der = None
            issuer_cert_error = None
            issuer_cert_source = None
            if skip_aia_issuer_download:
                logger.debug(f"略過 AIA issuer 憑證下載（使用者已指定 issuer_url）")
                issuer_cert_error = 'skipped_by_user_issuer_url'
            elif issuer_cert_url:
                logger.debug(f"從 AIA 提取 issuer 憑證 URL: {issuer_cert_url}")
                issuer_certificate_der, issuer_cert_error = self._download_issuer_certificate(issuer_cert_url)
                issuer_cert_source = 'aia'
                if issuer_certificate_der:
                    logger.info(f"成功從 AIA 下載 issuer 憑證: {issuer_cert_url}")
                else:
                    logger.warning(f"從 AIA 下載 issuer 憑證失敗: {issuer_cert_url}, error={issuer_cert_error}")
            else:
                issuer_cert_error = 'no_issuer_cert_url'
            
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
                'issuer_cert_url': issuer_cert_url,
                'issuer_certificate_der': issuer_certificate_der,
                'issuer_cert_error': issuer_cert_error,
                'issuer_cert_source': issuer_cert_source,
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
