"""
網站憑證監控系統 - 主程式

後台服務：定期監控 SSL/TLS 憑證，檢查有效性並發送告警。
"""

import sys
from pathlib import Path

# 確保能找到同級模組
_src_path = Path(__file__).resolve().parent
if str(_src_path) not in sys.path:
    sys.path.insert(0, str(_src_path))

import logging.config
import logging
import signal
import time
from urllib.parse import urlparse

from config_loader import ConfigLoader
from certificate_checker import CertificateChecker
from validators import ExpiredValidator, RevokedValidator
from notifier import EmailNotifier
from scheduler import CertificateCheckScheduler


def setup_logging():
    """
    根據 logging.yaml 設定日誌系統
    """
    project_root = Path(__file__).resolve().parent.parent
    logs_dir = project_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    logging_config_path = project_root / "config" / "logging.yaml"
    
    if not logging_config_path.exists():
        # 如果沒有 logging.yaml，使用基本配置
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logging.warning(f"找不到日誌設定檔: {logging_config_path}")
        return
    
    try:
        import yaml
        with open(logging_config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        for handler_name in ("file", "error_file"):
            handler_config = config.get("handlers", {}).get(handler_name)
            if handler_config and "filename" in handler_config:
                handler_config["filename"] = str(project_root / handler_config["filename"])

        logging.config.dictConfig(config)
        logging.info("日誌系統初始化完成")
    except Exception as e:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        logging.error(f"載入日誌設定失敗: {e}")


class CertificateMonitor:
    """憑證監控系統主控制器"""
    
    def __init__(self, config_path: str = None):
        """
        初始化監控系統
        
        參數：
            config_path: 配置檔路徑
        """
        self.logger = logging.getLogger(__name__)
        
        if config_path is None:
            config_path = str(Path(__file__).parent.parent / "config" / "sites.yaml")
        
        self.config_loader = ConfigLoader(config_path)
        self.network_config = None
        self.certificate_checker = None
        self.email_notifier = None
        self.scheduler = None
        self.running = False
        
        self._load_config()
    
    def _load_config(self):
        """載入並驗證配置"""
        try:
            self.config_loader.load()
            self.config_loader.validate()
            self.network_config = self.config_loader.get_network_config()
            self.certificate_checker = CertificateChecker(self.network_config)
            
            email_config = self.config_loader.get_email_config()
            if email_config:
                self.email_notifier = EmailNotifier(email_config)
            else:
                self.email_notifier = None
                self.logger.warning("未設定 email.yaml，郵件通知功能停用")
            
            check_interval = self.config_loader.get_check_interval()
            self.scheduler = CertificateCheckScheduler(check_interval)
            
            self.logger.info("配置載入和驗證完成")
            
        except Exception as e:
            self.logger.error(f"配置載入失敗: {e}")
            raise
    
    def check_certificate(self, site: dict) -> dict:
        """
        檢查單一網站的憑證
        
        參數：
            site: 監控網站配置
        
        返回：
            {
                'url': 網址,
                'status': 'ok' | 'alert',
                'expected': 預期狀態,
                'actual': 實際狀態,
                'message': 訊息,
                'cert_info': 憑證資訊
            }
        """
        url = site['url']
        expected_status = site['expected_status']
        
        self.logger.info(f"正在檢查: {url} (預期: {expected_status})")
        
        result = {
            'url': url,
            'expected': expected_status,
            'actual': None,
            'status': 'ok',
            'message': '',
            'cert_info': None,
            'check_results': {
                'url_check': {'status': 'skipped', 'message': '', 'details': {}},
                'expiry_check': {'status': 'skipped', 'message': '', 'details': {}},
                'crl_check': {'status': 'skipped', 'message': '', 'details': {}},
                'ocsp_check': {'status': 'skipped', 'message': '', 'details': {}},
                'overall_result': {'status': 'failed', 'message': '尚未開始檢查'}
            }
        }
        
        try:
            # 解析 URL 取得主機名
            parsed = urlparse(url)
            hostname = parsed.hostname or parsed.netloc or parsed.path
            port = parsed.port or 443

            # URL 連線檢查（失敗即停止後續檢查）
            cert_der = self.certificate_checker.get_certificate(hostname, port)
            result['check_results']['url_check'] = {
                'status': 'passed',
                'message': f'可連線到 {hostname}:{port}',
                'details': {'hostname': hostname, 'port': port}
            }

            # 連線成功後才解析憑證
            cert_info = self.certificate_checker.parse_certificate(cert_der)
            cert_info['ocsp_url'] = site.get('ocsp_url')
            cert_info['ocsp_url_source'] = 'sites_yaml'

            issuer_url = (site.get('issuer_url') or '').strip()
            if issuer_url:
                issuer_der, issuer_error = self.certificate_checker.load_issuer_certificate_from_url(issuer_url)
                cert_info['issuer_cert_url'] = issuer_url
                cert_info['issuer_cert_source'] = 'sites_yaml'
                cert_info['issuer_certificate_der'] = issuer_der
                cert_info['issuer_cert_error'] = issuer_error

            result['cert_info'] = cert_info

            # 1) 效期檢查
            expired_validator = ExpiredValidator()
            expired_result = expired_validator.validate(cert_info)
            is_expired = bool(expired_result.get('details', {}).get('is_expired', False))
            expected_expired = expected_status == 'expired'
            expiry_passed = is_expired == expected_expired
            result['check_results']['expiry_check'] = {
                'status': 'passed' if expiry_passed else 'failed',
                'message': (
                    f"效期檢查符合預期（expected={expected_status}, is_expired={is_expired})"
                    if expiry_passed else
                    f"效期檢查不符合預期（expected={expected_status}, is_expired={is_expired})"
                ),
                'details': expired_result.get('details', {})
            }

            # 2) 吊銷檢查（CRL + OCSP）
            revoked_validator = RevokedValidator(self.network_config)
            revoked_result = revoked_validator.validate(cert_info)
            revoked_details = revoked_result.get('details', {})
            crl_raw = revoked_details.get('crl_check')
            ocsp_raw = revoked_details.get('ocsp_check')
            expected_revoked = expected_status == 'revoked'

            if not crl_raw:
                result['check_results']['crl_check'] = {
                    'status': 'failed',
                    'message': 'CRL 檢查無結果',
                    'details': {}
                }
            elif crl_raw.get('status') != 'passed' or crl_raw.get('revoked') is None:
                result['check_results']['crl_check'] = {
                    'status': 'failed',
                    'message': crl_raw.get('message', 'CRL 檢查失敗'),
                    'details': crl_raw.get('details', {})
                }
            else:
                crl_revoked = bool(crl_raw.get('revoked'))
                crl_passed = crl_revoked == expected_revoked
                result['check_results']['crl_check'] = {
                    'status': 'passed' if crl_passed else 'failed',
                    'message': (
                        f"CRL 檢查符合預期（expected_revoked={expected_revoked}, actual_revoked={crl_revoked})"
                        if crl_passed else
                        f"CRL 檢查不符合預期（expected_revoked={expected_revoked}, actual_revoked={crl_revoked})"
                    ),
                    'details': crl_raw.get('details', {})
                }

            if not ocsp_raw:
                result['check_results']['ocsp_check'] = {
                    'status': 'failed',
                    'message': 'OCSP 檢查無結果',
                    'details': {}
                }
            else:
                ocsp_details = ocsp_raw.get('details', {})
                ocsp_status = ocsp_details.get('status')
                ocsp_validator_passed = ocsp_raw.get('status') == 'passed'

                # 業務規則：expired 場景中，只有真正收到 OCSP UNKNOWN 回應才算通過。
                if expected_status == 'expired':
                    ocsp_passed = ocsp_validator_passed and ocsp_status == 'unknown'
                    result['check_results']['ocsp_check'] = {
                        'status': 'passed' if ocsp_passed else 'failed',
                        'message': (
                            f"OCSP 檢查符合預期（expired 需為 unknown, actual_status={ocsp_status})"
                            if ocsp_passed else
                            f"OCSP 檢查不符合預期（expired 需為 unknown, actual_status={ocsp_status})"
                        ),
                        'details': ocsp_details
                    }
                elif ocsp_raw.get('status') != 'passed' or ocsp_raw.get('revoked') is None:
                    result['check_results']['ocsp_check'] = {
                        'status': 'failed',
                        'message': ocsp_raw.get('message', 'OCSP 檢查失敗'),
                        'details': ocsp_details
                    }
                else:
                    ocsp_revoked = bool(ocsp_raw.get('revoked'))
                    ocsp_passed = ocsp_revoked == expected_revoked
                    result['check_results']['ocsp_check'] = {
                        'status': 'passed' if ocsp_passed else 'failed',
                        'message': (
                            f"OCSP 檢查符合預期（expected_revoked={expected_revoked}, actual_revoked={ocsp_revoked})"
                            if ocsp_passed else
                            f"OCSP 檢查不符合預期（expected_revoked={expected_revoked}, actual_revoked={ocsp_revoked})"
                        ),
                        'details': ocsp_details
                    }

            # 3) 綜合結果：任一 failed 即 failed
            sub_checks = (
                result['check_results']['url_check'],
                result['check_results']['expiry_check'],
                result['check_results']['crl_check'],
                result['check_results']['ocsp_check']
            )
            has_failed = any(item.get('status') == 'failed' for item in sub_checks)

            result['check_results']['overall_result'] = {
                'status': 'failed' if has_failed else 'passed',
                'message': '至少一項檢查失敗' if has_failed else '所有檢查均通過'
            }

            if has_failed:
                result['actual'] = 'failed'
                result['status'] = 'alert'
                result['message'] = '檢查失敗（請查看 check_results）'
            else:
                result['actual'] = expected_status
                result['message'] = '檢查通過'
            
            self.logger.info(f"檢查完成: {url} -> {result['actual']}")
            return result
            
        except Exception as e:
            self.logger.error(f"檢查失敗: {url} -> {e}")
            result['check_results']['url_check'] = {
                'status': 'failed',
                'message': f"URL 連線失敗: {str(e)}",
                'details': {'error': str(e)}
            }
            result['check_results']['expiry_check'] = {
                'status': 'skipped',
                'message': '因 URL 連線失敗而跳過',
                'details': {'reason': 'blocked_by_url_failure'}
            }
            result['check_results']['crl_check'] = {
                'status': 'skipped',
                'message': '因 URL 連線失敗而跳過',
                'details': {'reason': 'blocked_by_url_failure'}
            }
            result['check_results']['ocsp_check'] = {
                'status': 'skipped',
                'message': '因 URL 連線失敗而跳過',
                'details': {'reason': 'blocked_by_url_failure'}
            }
            result['check_results']['overall_result'] = {
                'status': 'failed',
                'message': 'URL 連線失敗，後續檢查已停止'
            }
            result['status'] = 'alert'
            result['actual'] = 'failed'
            result['message'] = result['check_results']['overall_result']['message']
            
            return result
    
    def check_all_certificates(self):
        """檢查所有配置的網站"""
        self.logger.info("=" * 50)
        self.logger.info("開始定期檢查")
        self.logger.info("=" * 50)
        
        sites = self.config_loader.get_sites()
        results = []
        
        for site in sites:
            result = self.check_certificate(site)
            results.append(result)
        
        # 彙總結果
        alert_count = sum(1 for r in results if r['status'] == 'alert')
        ok_count = sum(1 for r in results if r['status'] == 'ok')
        
        self._send_summary_email(results, ok_count, alert_count)
        
        self.logger.info(f"檢查完成: {len(results)} 個網站，{ok_count} 個正常，{alert_count} 個告警")
        self.logger.info("=" * 50)
    
    def _send_summary_email(self, results: list[dict], ok_count: int, alert_count: int):
        """發送整輪檢查摘要郵件"""
        if not self.email_notifier:
            self.logger.warning("郵件通知器未初始化")
            return
        
        try:
            self.email_notifier.send_summary_report(results, ok_count, alert_count)
        except Exception as e:
            self.logger.error(f"發送摘要郵件失敗: {e}")
    
    def start(self):
        """啟動監控服務"""
        if self.running:
            self.logger.warning("監控服務已在執行中")
            return
        
        try:
            self.logger.info("啟動監控服務...")
            
            # 設定調度器的檢查函數
            self.scheduler.set_check_function(self.check_all_certificates)
            
            # 啟動調度器
            self.scheduler.start()
            
            self.running = True
            self.logger.info("監控服務已啟動")
            
            # 設定信號處理
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
        except Exception as e:
            self.logger.error(f"啟動服務失敗: {e}")
            raise
    
    def stop(self):
        """停止監控服務"""
        if not self.running:
            self.logger.warning("監控服務尚未執行")
            return
        
        try:
            self.logger.info("停止監控服務...")
            self.scheduler.stop()
            self.running = False
            self.logger.info("監控服務已停止")
        except Exception as e:
            self.logger.error(f"停止服務失敗: {e}")
            raise
    
    def _signal_handler(self, signum, frame):
        """信號處理器（優雅關閉）"""
        self.logger.info(f"接收到信號 {signum}，準備關閉...")
        self.stop()
        sys.exit(0)


def main():
    """
    主程式入點
    """
    # 初始化日誌
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("網站憑證監控系統啟動")
    logger.info("=" * 60)
    
    monitor = None
    
    try:
        # 初始化監控系統
        config_path = Path(__file__).parent.parent / "config" / "sites.yaml"
        monitor = CertificateMonitor(str(config_path))
        
        # 列出監控目標
        sites = monitor.config_loader.get_sites()
        logger.info(f"共有 {len(sites)} 個監控目標:")
        for site in sites:
            logger.info(f"  - {site['url']} (預期狀態: {site['expected_status']})")
        
        # 啟動監控服務
        monitor.start()
        
        # Windows 沒有 signal.pause()，改用可攜式輪詢等待。
        logger.info("服務執行中（按 Ctrl+C 停止）...")
        while True:
            time.sleep(1)
        
    except FileNotFoundError as e:
        logger.error(f"檔案不存在: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"設定驗證失敗: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("接收到中斷信號")
        if monitor:
            monitor.stop()
    except Exception as e:
        logger.error(f"發生未預期的錯誤: {e}", exc_info=True)
        sys.exit(1)



if __name__ == "__main__":
    main()
