"""
驗證器模組

定義憑證驗證策略：good、expired、revoked
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging

from crl_checker import CRLChecker
from ocsp_checker import OCSPChecker

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
            
            logger.info(f"效期驗證完成: {result['message']}")
            return result
            
        except Exception as e:
            logger.error(f"過期驗證失敗: {e}")
            return {
                'status': 'failed',
                'message': f"驗證過程出錯: {str(e)}",
                'details': {}
            }


class RenewalValidator(CertificateValidator):
    """
    續約狀態驗證器
    
    檢查憑證是否在設定的更新期限內被重新申請/續約
    """
    
    def validate(self, cert_info: Dict[str, Any], renewal_days: int | None = None) -> Dict[str, Any]:
        """
        驗證憑證是否在續約期限內
        
        參數：
            cert_info: 憑證資訊
            renewal_days: 續約期限天數（None 表示未設定）
        
        返回：
            {
                'status': 'passed' | 'failed' | 'not_set',
                'message': '檢查訊息',
                'details': {
                    'renewal_days': int | None,
                    'days_since_issued': int,
                    'not_before': datetime ISO string
                }
            }
        """
        from datetime import datetime
        
        try:
            # 如果未設定續約檢查，返回 not_set
            if renewal_days is None:
                return {
                    'status': 'not_set',
                    'message': '未設定續約檢查',
                    'details': {
                        'renewal_days': None,
                        'days_since_issued': None,
                        'not_before': None
                    }
                }
            
            now = datetime.utcnow()
            not_before = cert_info['not_before']
            
            # 移除時區資訊
            if not_before.tzinfo is not None:
                not_before = not_before.replace(tzinfo=None)
            
            # 計算憑證已發行的天數
            time_diff = now - not_before
            days_since_issued = time_diff.days
            
            # 邏輯：如果憑證已發行天數 < renewal_days，則通過；否則失敗
            passed = days_since_issued < renewal_days
            
            if passed:
                message = f"憑證在 {renewal_days} 天內已續約（已發行 {days_since_issued} 天）"
            else:
                message = f"憑證未在 {renewal_days} 天內續約（已發行 {days_since_issued} 天）"
            
            result = {
                'status': 'passed' if passed else 'failed',
                'message': message,
                'details': {
                    'renewal_days': renewal_days,
                    'days_since_issued': days_since_issued,
                    'not_before': not_before.isoformat()
                }
            }
            
            logger.info(f"續約檢查完成: {result['message']}")
            return result
            
        except Exception as e:
            logger.error(f"續約檢查失敗: {e}")
            return {
                'status': 'failed',
                'message': f"驗證過程出錯: {str(e)}",
                'details': {
                    'renewal_days': renewal_days,
                    'days_since_issued': None,
                    'not_before': None
                }
            }


class RevokedValidator(CertificateValidator):
    """
    吊銷狀態驗證器
    
    檢查憑證是否已被吊銷（使用 CRL 和 OCSP）
    """
    
    def __init__(self, network_config: Dict[str, Any] | None = None):
        self.crl_checker = CRLChecker(network_config)
        self.ocsp_checker = OCSPChecker(network_config)
    
    def validate(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        驗證憑證是否已吊銷

        嚴格模式：CRL 與 OCSP 都必須成功且結果一致。
        """
        try:
            # 兩個檢查都要執行，並保留獨立結果
            crl_result = self._check_crl(cert_info)
            ocsp_result = self._check_ocsp(cert_info)

            if crl_result['status'] != 'passed' or ocsp_result['status'] != 'passed':
                return {
                    'status': 'failed',
                    'message': 'CRL 或 OCSP 檢查失敗',
                    'details': {
                        'crl_check': crl_result,
                        'ocsp_check': ocsp_result,
                        'revoked_consensus': None
                    }
                }

            if crl_result['revoked'] != ocsp_result['revoked']:
                return {
                    'status': 'failed',
                    'message': 'CRL 與 OCSP 結果不一致',
                    'details': {
                        'crl_check': crl_result,
                        'ocsp_check': ocsp_result,
                        'revoked_consensus': None
                    }
                }

            revoked_consensus = bool(crl_result['revoked'])
            return {
                'status': 'verified' if revoked_consensus else 'failed',
                'message': '憑證已被吊銷（CRL 與 OCSP 一致）' if revoked_consensus else '憑證未被吊銷（CRL 與 OCSP 一致）',
                'details': {
                    'crl_check': crl_result,
                    'ocsp_check': ocsp_result,
                    'revoked_consensus': revoked_consensus
                }
            }
            
        except Exception as e:
            logger.error(f"吊銷驗證失敗: {e}")
            return {
                'status': 'failed',
                'message': f"吊銷驗證過程出錯: {str(e)}",
                'details': {
                    'crl_check': None,
                    'ocsp_check': None,
                    'revoked_consensus': None
                }
            }
    
    def _check_ocsp(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """OCSP 驗證"""
        result = self.ocsp_checker.check_revocation(
            cert_der=cert_info.get('certificate_der'),
            issuer_der=cert_info.get('issuer_certificate_der'),
            ocsp_url=cert_info.get('ocsp_url')
        )

        revoked = result.get('revoked')
        if result.get('status') == 'unknown' and result.get('error') == 'ocsp_unknown_status':
            return {
                'name': 'ocsp',
                'status': 'passed',
                'revoked': None,
                'message': result.get('message', 'OCSP 回應為未知狀態'),
                'details': result
            }

        if revoked is None:
            return {
                'name': 'ocsp',
                'status': 'failed',
                'revoked': None,
                'message': result.get('message', 'OCSP 檢查失敗'),
                'details': result
            }

        return {
            'name': 'ocsp',
            'status': 'passed',
            'revoked': bool(revoked),
            'message': result.get('message', ''),
            'details': result
        }
    
    def _check_crl(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """CRL 驗證"""
        result = self.crl_checker.check_revocation(
            cert_der=cert_info.get('certificate_der'),
            crl_urls=cert_info.get('crl_distribution_points', [])
        )

        revoked = result.get('revoked')
        if revoked is None:
            return {
                'name': 'crl',
                'status': 'failed',
                'revoked': None,
                'message': result.get('message', 'CRL 檢查失敗'),
                'details': result
            }

        return {
            'name': 'crl',
            'status': 'passed',
            'revoked': bool(revoked),
            'message': result.get('message', ''),
            'details': result
        }


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
            if revoked_check['status'] == 'failed' and revoked_check.get('details', {}).get('revoked_consensus') is None:
                return {
                    'status': 'failed',
                    'message': '吊銷狀態檢查失敗（CRL/OCSP）',
                    'details': revoked_check.get('details', {})
                }

            if revoked_check.get('details', {}).get('revoked_consensus') is True:
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
