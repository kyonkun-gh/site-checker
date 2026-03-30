"""
電子郵件通知模組

從 YAML 配置讀取 SMTP 設定，發送告警郵件。
"""

import logging
import smtplib
from typing import Dict, Any, List
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

logger = logging.getLogger(__name__)


class EmailNotifier:
    """電子郵件通知程序"""
    
    def __init__(self, email_config: Dict[str, Any]):
        """
        初始化郵件通知器
        
        參數：
            email_config: 從 YAML 讀取的電子郵件配置
                {
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'sender_email': 'alerts@example.com',
                    'sender_name': '憑證監控',
                    'sender_password': 'password' or None,
                    'recipients': ['admin@example.com']
                }
        """
        self.config = email_config
        self.enabled = email_config.get('enabled', True)  # 預設開啟
        self.smtp_server = email_config.get('smtp_server')
        self.smtp_port = email_config.get('smtp_port', 587)
        self.sender_email = email_config.get('sender_email')
        self.sender_name = email_config.get('sender_name', '系統通知')
        self.sender_password = email_config.get('sender_password')
        self.recipients = email_config.get('recipients', [])
        
        status = "已開啟" if self.enabled else "已關閉"
        logger.info(f"郵件通知器已初始化: {self.sender_email} ({status})")
    
    def send_summary_report(self,
                            results: List[Dict[str, Any]],
                            alert_count: int,
                            error_count: int) -> bool:
        """發送整輪檢查摘要郵件。"""
        if not self.enabled:
            logger.info("郵件通知已關閉，略過發送摘要信")
            return True
        
        total_count = len(results)
        has_issue = alert_count > 0 or error_count > 0

        if has_issue:
            subject = f"[異常] 憑證檢查結果 - {alert_count} 個告警，{error_count} 個錯誤"
            summary_text = (
                f"本輪共檢查 {total_count} 個網站，其中 {alert_count} 個告警、"
                f"{error_count} 個錯誤，請檢查下列異常項目。"
            )
        else:
            subject = f"[正常] 憑證檢查結果 - {total_count} 個網站皆正常"
            summary_text = f"本輪共檢查 {total_count} 個網站，全部結果正常。"

        plain_body = self._generate_summary_plain_body(summary_text, results)
        html_body = self._generate_summary_html_body(subject, summary_text, results, has_issue)
        return self._send_message(subject, plain_body, html_body)
    
    def send_alert(self, 
                  subject: str, 
                  body: str,
                  site_url: str = None,
                  cert_info: Dict[str, Any] = None) -> bool:
        """
        發送告警郵件
        
        參數：
            subject: 郵件主旨
            body: 郵件內容（純文字）
            site_url: 網站 URL（用於郵件內容）
            cert_info: 憑證資訊（用於郵件內容）
        
        返回：
            True 如果發送成功，False 否則
        """
        try:
            html_body = self._generate_html_body(subject, body, site_url, cert_info)
            return self._send_message(subject, body, html_body)
        except smtplib.SMTPException as e:
            logger.error(f"SMTP 錯誤: {e}")
            return False
        except Exception as e:
            logger.error(f"郵件發送失敗: {e}")
            return False

    def _send_message(self, subject: str, plain_body: str, html_body: str) -> bool:
        """送出純文字與 HTML multipart 郵件。"""
        try:
            message = MIMEMultipart('alternative')
            message['Subject'] = Header(subject, 'utf-8')
            message['From'] = f"{self.sender_name} <{self.sender_email}>"
            message['To'] = ', '.join(self.recipients)

            part_plain = MIMEText(plain_body, 'plain', 'utf-8')
            part_html = MIMEText(html_body, 'html', 'utf-8')
            message.attach(part_plain)
            message.attach(part_html)

            logger.debug(f"正在連接 SMTP 伺服器: {self.smtp_server}:{self.smtp_port}")

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()

                if self.sender_password:
                    logger.debug("執行 SMTP 認證")
                    server.login(self.sender_email, self.sender_password)

                server.send_message(message)

            logger.info(f"郵件發送成功: {', '.join(self.recipients)}")
            return True
        except smtplib.SMTPException as e:
            logger.error(f"SMTP 錯誤: {e}")
            return False
        except Exception as e:
            logger.error(f"郵件發送失敗: {e}")
            return False
    
    def _generate_html_body(self, 
                           subject: str, 
                           body: str,
                           site_url: str = None,
                           cert_info: Dict[str, Any] = None) -> str:
        """
        生成 HTML 格式的郵件內容
        """
        html_parts = [
            "<html>",
            "<head><meta charset='utf-8'></head>",
            "<body style='font-family: Arial, sans-serif; line-height: 1.6;'>",
            f"<h2 style='color: #d32f2f;'>{subject}</h2>",
            f"<p>{body}</p>"
        ]
        
        if site_url:
            html_parts.append(f"<p><strong>網站:</strong> {site_url}</p>")
        
        if cert_info:
            html_parts.append("<hr>")
            html_parts.append("<h3>憑證詳細資訊：</h3>")
            html_parts.append("<ul>")
            
            if 'subject' in cert_info:
                html_parts.append(f"<li><strong>主體：</strong> {cert_info['subject']}</li>")
            if 'issuer' in cert_info:
                html_parts.append(f"<li><strong>發行者：</strong> {cert_info['issuer']}</li>")
            if 'not_after' in cert_info:
                html_parts.append(f"<li><strong>過期時間：</strong> {cert_info['not_after']}</li>")
            if 'serial_number' in cert_info:
                html_parts.append(f"<li><strong>憑證序號：</strong> {cert_info['serial_number']}</li>")
            
            html_parts.append("</ul>")
        
        html_parts.extend([
            "<hr>",
            f"<p style='color: #666; font-size: 12px;'>此為自動告警郵件，請勿回覆。</p>",
            "</body>",
            "</html>"
        ])
        
        return '\n'.join(html_parts)

    def _generate_summary_plain_body(self, summary_text: str, results: List[Dict[str, Any]]) -> str:
        """生成整輪檢查的純文字摘要內容。"""
        status_map = {
            'ok': '正常',
            'alert': '異常',
            'error': '錯誤'
        }
        expected_map = {
            'good': '正常',
            'expired': '已過期',
            'revoked': '已吊銷'
        }

        lines = [summary_text, "", "檢查明細："]

        for index, result in enumerate(results, start=1):
            lines.extend([
                f"{index}. 網站: {result.get('url')}",
                f"   狀態: {status_map.get(result.get('status'), result.get('status'))}",
                f"   預期: {expected_map.get(result.get('expected'), result.get('expected'))}",
                f"   實際結果: {result.get('message', '')}",
            ])

            cert_info = result.get('cert_info') or {}
            if cert_info:
                if cert_info.get('subject'):
                    lines.append(f"   憑證主體: {cert_info['subject']}")
                if cert_info.get('issuer'):
                    lines.append(f"   發行者: {cert_info['issuer']}")
                if cert_info.get('not_after'):
                    lines.append(f"   過期時間: {cert_info['not_after']}")

            lines.append("")

        lines.append("此為自動檢查郵件，請勿直接回覆。")
        return "\n".join(lines)

    def _generate_summary_html_body(self,
                                    subject: str,
                                    summary_text: str,
                                    results: List[Dict[str, Any]],
                                    has_issue: bool) -> str:
        """生成整輪檢查的 HTML 摘要內容。"""
        accent_color = '#d32f2f' if has_issue else '#2e7d32'
        status_map = {
            'ok': '正常',
            'alert': '異常',
            'error': '錯誤'
        }
        expected_map = {
            'good': '正常',
            'expired': '已過期',
            'revoked': '已吊銷'
        }

        html_parts = [
            "<html>",
            "<head><meta charset='utf-8'></head>",
            "<body style='font-family: Arial, sans-serif; line-height: 1.6; color: #222;'>",
            f"<h2 style='color: {accent_color};'>{subject}</h2>",
            f"<p>{summary_text}</p>",
            "<table style='border-collapse: collapse; width: 100%; margin-top: 16px;'>",
            "<thead>",
            "<tr>",
            "<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>網站</th>",
            "<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>狀態</th>",
            "<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>預期</th>",
            "<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>結果</th>",
            "<th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>憑證資訊</th>",
            "</tr>",
            "</thead>",
            "<tbody>",
        ]

        for result in results:
            cert_info = result.get('cert_info') or {}
            cert_lines = []
            if cert_info.get('subject'):
                cert_lines.append(f"主體: {cert_info['subject']}")
            if cert_info.get('issuer'):
                cert_lines.append(f"發行者: {cert_info['issuer']}")
            if cert_info.get('not_after'):
                cert_lines.append(f"過期時間: {cert_info['not_after']}")

            html_parts.extend([
                "<tr>",
                f"<td style='border: 1px solid #ddd; padding: 8px; vertical-align: top;'>{result.get('url')}</td>",
                f"<td style='border: 1px solid #ddd; padding: 8px; vertical-align: top;'>{status_map.get(result.get('status'), result.get('status'))}</td>",
                f"<td style='border: 1px solid #ddd; padding: 8px; vertical-align: top;'>{expected_map.get(result.get('expected'), result.get('expected'))}</td>",
                f"<td style='border: 1px solid #ddd; padding: 8px; vertical-align: top;'>{result.get('message', '')}</td>",
                f"<td style='border: 1px solid #ddd; padding: 8px; vertical-align: top;'>{'<br>'.join(cert_lines) if cert_lines else '-'}</td>",
                "</tr>",
            ])

        html_parts.extend([
            "</tbody>",
            "</table>",
            "<hr>",
            "<p style='color: #666; font-size: 12px;'>此為自動檢查郵件，請勿直接回覆。</p>",
            "</body>",
            "</html>",
        ])

        return '\n'.join(html_parts)
    
    def send_test_email(self) -> bool:
        """
        發送測試郵件以驗證配置
        
        返回：
            True 如果發送成功
        """
        return self.send_alert(
            subject="[測試] 憑證監控系統郵件測試",
            body="如果你收到此郵件，表示郵件配置正確。"
        )
