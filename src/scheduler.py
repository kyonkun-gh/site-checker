"""
後台調度模組

使用 APScheduler 定期執行憑證檢查任務。
"""

import logging
from typing import Callable, List, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime

logger = logging.getLogger(__name__)


class CertificateCheckScheduler:
    """憑證檢查調度器"""
    
    def __init__(self, check_interval_hours: Optional[int] = None, check_times: Optional[List[str]] = None):
        """
        初始化調度器
        
        參數：
            check_interval_hours: 檢查間隔（小時）
            check_times: 每日固定檢查時間（HH:MM）
        """
        self.scheduler = BackgroundScheduler()
        self.check_interval_hours = check_interval_hours
        self.check_times = check_times or []
        self.check_function = None
        self.is_running = False

        has_interval = check_interval_hours is not None
        has_check_times = bool(self.check_times)
        if has_interval == has_check_times:
            raise ValueError("排程設定錯誤：check_interval_hours 與 check_times 必須且只能擇一設定")

        self.mode = "interval" if has_interval else "times"
        
        if self.mode == "interval":
            logger.info(f"調度器已初始化（interval 模式），檢查間隔: {check_interval_hours} 小時")
        else:
            logger.info(f"調度器已初始化（time 模式），固定時間: {', '.join(self.check_times)}")

    def _parse_time(self, time_str: str):
        """解析 HH:MM 字串為 hour, minute。"""
        hour, minute = time_str.split(":")
        return int(hour), int(minute)
    
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
            if self.mode == "interval":
                trigger = IntervalTrigger(hours=self.check_interval_hours)
                self.scheduler.add_job(
                    self.check_function,
                    trigger=trigger,
                    id='certificate_check_interval',
                    name='定期憑證檢查（間隔）',
                    replace_existing=True
                )
            else:
                for check_time in self.check_times:
                    hour, minute = self._parse_time(check_time)
                    trigger = CronTrigger(hour=hour, minute=minute)
                    self.scheduler.add_job(
                        self.check_function,
                        trigger=trigger,
                        id=f"certificate_check_{check_time.replace(':', '')}",
                        name=f"定期憑證檢查（{check_time}）",
                        replace_existing=True
                    )
            
            self.scheduler.start()
            self.is_running = True
            
            if self.mode == "interval":
                logger.info(f"調度服務已啟動，每 {self.check_interval_hours} 小時檢查一次")
            else:
                logger.info(f"調度服務已啟動，每日固定時間檢查: {', '.join(self.check_times)}")
            
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
            jobs = self.scheduler.get_jobs()
            next_run_times = [job.next_run_time for job in jobs if job.next_run_time is not None]
            if next_run_times:
                return min(next_run_times)
        except Exception as e:
            logger.debug(f"獲取下次執行時間失敗: {e}")
        
        return None
