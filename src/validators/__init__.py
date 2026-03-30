"""
驗證器模組

定義憑證驗證策略：good、expired、revoked
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class CertificateValidator(ABC):
    """憑證驗證器基類"""
    
    @abstractmethod
    def validate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        驗證憑證
        
        參數：
            cert_info: 憑證資訊字典（來自 CertificateChecker.parse_certificate()）
        
        返回：
            {
                'status': 'verified' | 'failed',
                'message': '驗證訊息',
                'details': {...}  # 額外細節
            }
        """
        pass


class ExpiredValidator(CertificateValidator):
    """
    過期狀態驗證器
    
    檢查憑證是否已過期
    """
    
    def validate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """驗證憑證是否已過期"""
        from datetime import datetime
        
        try:
            now = datetime.utcnow()
            not_after = cert_info['not_after']
            
            # 移除時區資訊
            if not_after.tzinfo is not None:
                not_after = not_after.replace(tzinfo=None)
            
            is_expired = now > not_after
            
            result = {
                'status': 'verified' if is_expired else 'failed',
                'message': f"憑證已過期" if is_expired else f"憑證尚未過期",
                'details': {
                    'not_after': not_after.isoformat(),
                    'current_time': now.isoformat(),
                    'is_expired': is_expired
                }
            }
            
            logger.info(f"過期驗證完成: {result['message']}")
            return result
            
        except Exception as e:
            logger.error(f"過期驗證失敗: {e}")
            return {
                'status': 'failed',
                'message': f"驗證過程出錯: {str(e)}",
                'details': {}
            }


class RevokedValidator(CertificateValidator):
    """
    吊銷狀態驗證器
    
    檢查憑證是否已被吊銷（使用 CRL 和 OCSP）
    """
    
    def __init__(self):
        self.crl_checker = None
        self.ocsp_checker = None
    
    def validate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        驗證憑證是否已吊銷
        
        檢查順序：OCSP（快速）-> CRL（備用）
        """
        try:
            # 嘗試 OCSP 驗證
            ocsp_result = self._check_ocsp(cert_info)
            if ocsp_result:
                return ocsp_result
            
            # 備用：CRL 驗證
            crl_result = self._check_crl(cert_info)
            if crl_result:
                return crl_result
            
            # 如果都無法驗證
            return {
                'status': 'inconclusive',
                'message': '無法驗證憑證吊銷狀態（OCSP 和 CRL 都不可用）',
                'details': {}
            }
            
        except Exception as e:
            logger.error(f"吊銷驗證失敗: {e}")
            return {
                'status': 'failed',
                'message': f"吊銷驗證過程出錯: {str(e)}",
                'details': {}
            }
    
    def _check_ocsp(self, cert_info: Dict[str, Any]) -> Dict[str, Any] | None:
        """OCSP 驗證（待實裝）"""
        logger.debug("OCSP 驗證模組待實裝")
        return None
    
    def _check_crl(self, cert_info: Dict[str, Any]) -> Dict[str, Any] | None:
        """CRL 驗證（待實裝）"""
        logger.debug("CRL 驗證模組待實裝")
        return None


class GoodValidator(CertificateValidator):
    """
    正常狀態驗證器
    
    檢查憑證是否有效（未過期且未被吊銷）
    """
    
    def __init__(self):
        self.expired_validator = ExpiredValidator()
        self.revoked_validator = RevokedValidator()
    
    def validate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        驗證憑證是否正常（同時檢查過期和吊銷狀態）
        """
        try:
            # 檢查是否過期
            expired_check = self.expired_validator.validate(cert_info)
            if expired_check['status'] == 'verified':  # 如果驗證為「已過期」
                return {
                    'status': 'failed',
                    'message': '憑證已過期',
                    'details': expired_check.get('details', {})
                }
            
            # 檢查是否被吊銷
            revoked_check = self.revoked_validator.validate(cert_info)
            if revoked_check['status'] == 'verified':  # 如果驗證為「已吊銷」
                return {
                    'status': 'failed',
                    'message': '憑證已被吊銷',
                    'details': revoked_check.get('details', {})
                }
            
            # 兩項檢查都通過
            return {
                'status': 'verified',
                'message': '憑證正常（未過期且未被吊銷）',
                'details': {
                    'expired_status': expired_check['status'],
                    'revoked_status': revoked_check['status']
                }
            }
            
        except Exception as e:
            logger.error(f"正常狀態驗證失敗: {e}")
            return {
                'status': 'failed',
                'message': f"驗證過程出錯: {str(e)}",
                'details': {}
            }


def get_validator(expected_status: str) -> CertificateValidator:
    """
    根據預期狀態取得對應的驗證器
    
    參數：
        expected_status: 預期狀態 ('good', 'expired', 'revoked')
    
    返回：
        CertificateValidator 子類實例
    
    拋出：
        ValueError: 未知的狀態
    """
    validators = {
        'good': GoodValidator,
        'expired': ExpiredValidator,
        'revoked': RevokedValidator
    }
    
    if expected_status not in validators:
        raise ValueError(f"未知的驗證狀態: {expected_status}")
    
    return validators[expected_status]()
