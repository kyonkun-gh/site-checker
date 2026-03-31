"""
OCSP（線上憑證狀態協議）檢查模組

透過 OCSP 回應器查詢憑證吊銷狀態。
"""

import logging
from typing import Dict, Any, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.ocsp import (
        OCSPRequestBuilder,
        OCSPResponseStatus,
        OCSPCertStatus,
        load_der_ocsp_response,
    )
    import requests
except ImportError:
    raise ImportError("需要安裝: cryptography, requests")

logger = logging.getLogger(__name__)


class OCSPChecker:
    """OCSP 驗證檢查器"""
    
    # 請求超時設定（秒）
    TIMEOUT = 10
    
    def __init__(self):
        self.backend = default_backend()
    
    def check_revocation(self, 
                        cert_der: bytes, 
                        issuer_der: Optional[bytes] = None,
                        ocsp_url: Optional[str] = None) -> Dict[str, Any]:
        """
        透過 OCSP 檢查憑證是否被吊銷
        
        參數：
            cert_der: 憑證的 DER 編碼二進位內容
            issuer_der: 簽發者憑證的 DER 內容（可選）
            ocsp_url: OCSP 回應器 URL（由外部設定提供）
        
        返回：
            {
                'revoked': True | False | None,
                'message': '驗證訊息',
                'status': 'good' | 'revoked' | 'unknown',
                'ocsp_url': '使用的 OCSP URL',
                'error': '如果有錯誤'
            }
        """
        try:
            cert = x509.load_der_x509_certificate(cert_der, self.backend)
            
            if not ocsp_url:
                logger.warning("沒有可用的 OCSP 回應器 URL")
                return {
                    'revoked': None,
                    'message': '沒有 OCSP 回應器可用',
                    'status': 'unknown',
                    'ocsp_url': None,
                    'error': 'no_ocsp_url'
                }

            if not issuer_der:
                logger.warning("缺少 issuer 憑證，無法進行 OCSP 驗證")
                return {
                    'revoked': None,
                    'message': '缺少 issuer 憑證，無法進行 OCSP 驗證',
                    'status': 'unknown',
                    'ocsp_url': ocsp_url,
                    'error': 'missing_issuer_cert'
                }

            issuer_cert = x509.load_der_x509_certificate(issuer_der, self.backend)
            
            logger.info(f"開始 OCSP 驗證: {ocsp_url}")
            
            # 嘗試 OCSP 驗證
            result = self._query_ocsp(cert, issuer_cert, ocsp_url)
            return result
            
        except Exception as e:
            logger.error(f"OCSP 驗證過程出錯: {e}")
            return {
                'revoked': None,
                'message': f"OCSP 驗證出錯: {str(e)}",
                'status': 'unknown',
                'error': 'query_error'
            }
    
    def _extract_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """從憑證提取 OCSP 回應器 URL"""
        try:
            from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
            
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            
            for desc in aia.value:
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        return desc.access_location.value
        
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"提取 OCSP URL 失敗: {e}")
        
        return None
    
    def _query_ocsp(self, 
                   cert: x509.Certificate, 
                   issuer_cert: x509.Certificate,
                   ocsp_url: str) -> Dict[str, Any]:
        """
        查詢 OCSP 回應器
        
        注意：此實裝是簡化版，實際生產環境需要：
        - 驗簽發者憑證
        - 驗證 OCSP 回應簽名
        - 檢查 thisUpdate/nextUpdate 時間戳
        """
        try:
            logger.debug(f"向 OCSP 回應器發送請求: {ocsp_url}")
            
            # 建立 OCSP 請求（需包含簽發者憑證）
            builder = OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
            
            ocsp_request = builder.build()
            
            # 發送 OCSP 請求
            response = requests.post(
                ocsp_url,
                data=ocsp_request.public_bytes(serialization.Encoding.DER),
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=self.TIMEOUT
            )
            response.raise_for_status()
            
            logger.info(
                "OCSP 回應接收成功: http_status=%s, content_type=%s, content_length=%s",
                response.status_code,
                response.headers.get('Content-Type'),
                len(response.content),
            )

            ocsp_response = load_der_ocsp_response(response.content)
            logger.info(
                "OCSP 回應摘要: response_status=%s, cert_status=%s, this_update=%s, next_update=%s, "
                "revocation_time=%s, revocation_reason=%s",
                ocsp_response.response_status,
                ocsp_response.certificate_status,
                ocsp_response.this_update_utc,
                ocsp_response.next_update_utc,
                ocsp_response.revocation_time_utc,
                ocsp_response.revocation_reason,
            )
            if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
                return {
                    'revoked': None,
                    'message': f"OCSP 回應狀態非成功: {ocsp_response.response_status}",
                    'status': 'unknown',
                    'ocsp_url': ocsp_url,
                    'error': 'ocsp_response_not_successful'
                }

            cert_status = ocsp_response.certificate_status
            if cert_status == OCSPCertStatus.REVOKED:
                return {
                    'revoked': True,
                    'message': '憑證已被吊銷（根據 OCSP）',
                    'status': 'revoked',
                    'ocsp_url': ocsp_url
                }

            if cert_status == OCSPCertStatus.GOOD:
                return {
                    'revoked': False,
                    'message': '憑證狀態良好（根據 OCSP）',
                    'status': 'good',
                    'ocsp_url': ocsp_url
                }

            return {
                'revoked': None,
                'message': 'OCSP 回應為未知狀態',
                'status': 'unknown',
                'ocsp_url': ocsp_url,
                'error': 'ocsp_unknown_status'
            }
            
        except Exception as e:
            logger.error(f"OCSP 查詢失敗: {e}")
            return {
                'revoked': None,
                'message': f"OCSP 查詢失敗: {str(e)}",
                'status': 'unknown',
                'ocsp_url': ocsp_url,
                'error': 'query_failed'
            }
