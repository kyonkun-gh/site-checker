"""
網站憑證監控系統 - 主程式

後台服務：定期監控 SSL/TLS 憑證，檢查有效性並發送告警。
"""

import logging.config
import logging
import sys
import signal
import time
from pathlib import Path
from urllib.parse import urlparse

from config_loader import ConfigLoader
from certificate_checker import CertificateChecker
from validators import get_validator
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
        self.certificate_checker = CertificateChecker()
        self.email_notifier = None
        self.scheduler = None
        self.running = False
        
        self._load_config()
    
    def _load_config(self):
        """載入並驗證配置"""
        try:
            self.config_loader.load()
            self.config_loader.validate()
            
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
        
        self.logger.info(f"正在檢查: {url} (期望: {expected_status})")
        
        result = {
            'url': url,
            'expected': expected_status,
            'actual': None,
            'status': 'ok',
            'message': '',
            'cert_info': None
        }
        
        try:
            # 解析 URL 取得主機名
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path
            
            # 獲取憑證
            cert_der = self.certificate_checker.get_certificate(hostname)
            cert_info = self.certificate_checker.parse_certificate(cert_der)
            result['cert_info'] = cert_info
            
            # 根據預期狀態進行驗證
            validator = get_validator(expected_status)
            validation_result = validator.validate(cert_info)
            
            if validation_result['status'] == 'verified':
                result['actual'] = expected_status
                result['message'] = validation_result['message']
            else:
                result['actual'] = validation_result['status']
                result['status'] = 'alert'
                result['message'] = validation_result['message']
            
            self.logger.info(f"檢查完成: {url} -> {result['actual']}")
            return result
            
        except Exception as e:
            self.logger.error(f"檢查失敗: {url} -> {e}")
            result['status'] = 'error'
            result['actual'] = 'error'
            result['message'] = str(e)
            
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
        error_count = sum(1 for r in results if r['status'] == 'error')
        
        self._send_summary_email(results, alert_count, error_count)
        
        self.logger.info(f"檢查完成: {len(results)} 個網站，{alert_count} 個告警，{error_count} 個錯誤")
        self.logger.info("=" * 50)
    
    def _send_summary_email(self, results: list[dict], alert_count: int, error_count: int):
        """發送整輪檢查摘要郵件"""
        if not self.email_notifier:
            self.logger.warning("郵件通知器未初始化")
            return
        
        try:
            self.email_notifier.send_summary_report(results, alert_count, error_count)
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
            logger.info(f"  - {site['url']} (期望狀態: {site['expected_status']})")
        
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
