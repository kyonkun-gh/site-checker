"""
後台調度模組

使用 APScheduler 定期執行憑證檢查任務。
"""

import logging
from typing import Dict, Any, Callable
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime

logger = logging.getLogger(__name__)


class CertificateCheckScheduler:
    """憑證檢查調度器"""
    
    def __init__(self, check_interval_hours: int = 1):
        """
        初始化調度器
        
        參數：
            check_interval_hours: 檢查間隔（小時）
        """
        self.scheduler = BackgroundScheduler()
        self.check_interval_hours = check_interval_hours
        self.check_function = None
        self.is_running = False
        
        logger.info(f"調度器已初始化，檢查間隔: {check_interval_hours} 小時")
    
    def set_check_function(self, func: Callable):
        """
        設定檢查函數
        
        參數：
            func: 檢查函數，無參數，無返回值
                  例如: lambda: check_all_certificates()
        """
        self.check_function = func
        logger.info("檢查函數已設定")
    
    def start(self):
        """啟動調度服務"""
        if not self.check_function:
            raise ValueError("檢查函數未設定")
        
        if self.is_running:
            logger.warning("調度器已在執行中")
            return
        
        try:
            # 立即執行一次
            logger.info("執行初始檢查...")
            self.check_function()
            
            # 設定定期任務
            trigger = IntervalTrigger(hours=self.check_interval_hours)
            self.scheduler.add_job(
                self.check_function,
                trigger=trigger,
                id='certificate_check',
                name='定期憑證檢查',
                replace_existing=True
            )
            
            self.scheduler.start()
            self.is_running = True
            
            logger.info(f"調度服務已啟動，每 {self.check_interval_hours} 小時檢查一次")
            
        except Exception as e:
            logger.error(f"啟動調度器失敗: {e}")
            raise
    
    def stop(self):
        """停止調度服務"""
        if not self.is_running:
            logger.warning("調度器尚未執行")
            return
        
        try:
            self.scheduler.shutdown()
            self.is_running = False
            logger.info("調度服務已停止")
        except Exception as e:
            logger.error(f"停止調度器失敗: {e}")
            raise
    
    def get_next_run_time(self) -> datetime:
        """
        獲取下次檢查時間
        
        返回：
            datetime 物件，或 None 如果調度器未執行
        """
        try:
            job = self.scheduler.get_job('certificate_check')
            if job:
                return job.next_run_time
        except Exception as e:
            logger.debug(f"獲取下次執行時間失敗: {e}")
        
        return None
