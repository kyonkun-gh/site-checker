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
                    'smtp_username': 'smtp-user',
                    'smtp_password': 'password' or None,
                    'sender_email': 'alerts@example.com',
                    'sender_name': '憑證監控',
                    'recipients': ['admin@example.com']
                }
        """
        self.config = email_config
        self.enabled = email_config.get('enabled', True)  # 預設開啟
        self.smtp_server = email_config.get('smtp_server')
        self.smtp_port = email_config.get('smtp_port', 587)
        self.smtp_username = email_config.get('smtp_username') or email_config.get('sender_email')
        self.smtp_password = email_config.get('smtp_password')
        self.sender_email = email_config.get('sender_email')
        self.sender_name = email_config.get('sender_name', '系統通知')
        self.recipients = email_config.get('recipients', [])
        
        status = "已開啟" if self.enabled else "已關閉"
        logger.info(f"郵件通知器已初始化: {self.sender_email} ({status})")
    
    def send_summary_report(self,
                            results: List[Dict[str, Any]],
                            ok_count: int,
                            alert_count: int) -> bool:
        """發送整輪檢查摘要郵件。"""
        if not self.enabled:
            logger.info("郵件通知已關閉，略過發送摘要信")
            return True
        
        has_issue = alert_count > 0

        if has_issue:
            subject = f"[異常] 憑證檢查結果 - {ok_count}個正常，{alert_count}個告警"
            summary_text = (
                f"本輪共檢查 {len(results)} 個網站，其中 {ok_count} 個正常、"
                f"{alert_count} 個告警，請檢查下列異常項目。"
            )
        else:
            subject = f"[正常] 憑證檢查結果 - {ok_count}個正常，0個告警"
            summary_text = f"本輪共檢查 {len(results)} 個網站，{ok_count} 個正常，0 個告警。"

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

                if self.smtp_password:
                    logger.debug("執行 SMTP 認證")
                    server.login(self.smtp_username, self.smtp_password)

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
        expected_map = {
            'good': '正常',
            'expired': '已過期',
            'revoked': '已吊銷'
        }

        def check_label(status: str) -> str:
            if status == 'passed':
                return '通過'
            if status == 'failed':
                return '[失敗]'
            return '(跳過)'

        def fmt_dt(dt) -> str:
            if dt is None:
                return '-'
            try:
                return dt.strftime('%Y-%m-%d %H:%M UTC')
            except Exception:
                return str(dt)

        lines = [summary_text, "", "檢查明細：", ""]

        for index, result in enumerate(results, start=1):
            is_alert = result.get('status') in ('alert', 'error')
            site_tag = '[異常]' if is_alert else '[正常]'
            lines.append(f"{index}. {site_tag} 網站: {result.get('url')}")
            lines.append(f"   預期: {expected_map.get(result.get('expected'), result.get('expected'))}")
            lines.append("")

            cr = result.get('check_results') or {}
            lines.append("   檢查：")
            lines.append(f"   - 效期檢查: {check_label(cr.get('expiry_check', {}).get('status', 'skipped'))}")
            lines.append(f"   - CRL  檢查: {check_label(cr.get('crl_check', {}).get('status', 'skipped'))}")
            lines.append(f"   - OCSP 檢查: {check_label(cr.get('ocsp_check', {}).get('status', 'skipped'))}")
            lines.append("")

            cert_info = result.get('cert_info') or {}
            ocsp_msg = (cr.get('ocsp_check') or {}).get('details', {}).get('message', '-')
            lines.append("   憑證資訊：")
            lines.append(f"   - 主體    : {cert_info.get('subject') or '-'}")
            lines.append(f"   - 發行者  : {cert_info.get('issuer') or '-'}")
            lines.append(f"   - 起始時間: {fmt_dt(cert_info.get('not_before'))}")
            lines.append(f"   - 過期時間: {fmt_dt(cert_info.get('not_after'))}")
            lines.append(f"   - OCSP 回應: {ocsp_msg}")
            lines.append("")
            lines.append("   " + "-" * 40)
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
        expected_map = {
            'good': '正常',
            'expired': '已過期',
            'revoked': '已吊銷'
        }

        def badge(status: str) -> str:
            if status == 'passed':
                return "<span style='color:#2e7d32; font-weight:bold;'>通過</span>"
            if status == 'failed':
                return "<span style='color:#d32f2f; font-weight:bold;'>失敗</span>"
            return "<span style='color:#888;'>跳過</span>"

        def fmt_dt(dt) -> str:
            if dt is None:
                return '-'
            try:
                return dt.strftime('%Y-%m-%d %H:%M UTC')
            except Exception:
                return str(dt)

        td = "style='border:1px solid #e0e0e0; padding:6px 10px; vertical-align:top;'"
        th = "style='border:1px solid #e0e0e0; padding:6px 10px; background:#f5f5f5; font-weight:bold; text-align:left; vertical-align:top; white-space:nowrap;'"

        html_parts = [
            "<html>",
            "<head><meta charset='utf-8'></head>",
            "<body style='font-family:Arial, sans-serif; line-height:1.6; color:#222; max-width:800px;'>",
            f"<h2 style='color:{accent_color};'>{subject}</h2>",
            f"<p>{summary_text}</p>",
        ]

        for result in results:
            is_alert = result.get('status') in ('alert', 'error')
            card_border = '#d32f2f' if is_alert else '#4caf50'
            url_color   = '#d32f2f' if is_alert else '#1a237e'
            cr          = result.get('check_results') or {}
            cert_info   = result.get('cert_info') or {}

            expiry_status = (cr.get('expiry_check') or {}).get('status', 'skipped')
            crl_status    = (cr.get('crl_check')    or {}).get('status', 'skipped')
            ocsp_status   = (cr.get('ocsp_check')   or {}).get('status', 'skipped')
            ocsp_msg      = (cr.get('ocsp_check') or {}).get('details', {}).get('message', '-') or '-'

            def label_color(s: str) -> str:
                return '#d32f2f' if s == 'failed' else '#222'

            # 卡片開始
            html_parts.append(
                f"<div style='border-left:4px solid {card_border}; margin:16px 0; "
                f"padding:12px 16px; background:#fafafa; border-radius:0 4px 4px 0;'>"
            )

            # 網站標題與預期
            html_parts.append(
                f"<p style='margin:0 0 2px 0;'>"
                f"<strong style='color:{url_color}; font-size:15px;'>{result.get('url')}</strong>"
                f"</p>"
            )
            html_parts.append(
                f"<p style='margin:0 0 10px 0; color:#555;'>"
                f"預期狀態：{expected_map.get(result.get('expected'), result.get('expected'))}"
                f"</p>"
            )

            # 檢查結果表格
            html_parts.extend([
                "<p style='margin:0 0 4px 0;'><strong>檢查</strong></p>",
                "<table style='border-collapse:collapse; width:100%; margin-bottom:12px;'>",
                "<thead><tr>",
                f"<th {th}>檢查項目</th>",
                f"<th {th}>結果</th>",
                "</tr></thead>",
                "<tbody>",
                f"<tr>"
                f"<td {td}><span style='color:{label_color(expiry_status)};'>效期檢查</span></td>"
                f"<td {td}>{badge(expiry_status)}</td>"
                f"</tr>",
                f"<tr>"
                f"<td {td}><span style='color:{label_color(crl_status)};'>CRL 檢查</span></td>"
                f"<td {td}>{badge(crl_status)}</td>"
                f"</tr>",
                f"<tr>"
                f"<td {td}><span style='color:{label_color(ocsp_status)};'>OCSP 檢查</span></td>"
                f"<td {td}>{badge(ocsp_status)}</td>"
                f"</tr>",
                "</tbody></table>",
            ])

            # 憑證資訊表格
            html_parts.extend([
                "<p style='margin:0 0 4px 0;'><strong>憑證資訊</strong></p>",
                "<table style='border-collapse:collapse; width:100%;'>",
                "<tbody>",
                f"<tr><td {th}>主體</td><td {td}>{cert_info.get('subject') or '-'}</td></tr>",
                f"<tr><td {th}>發行者</td><td {td}>{cert_info.get('issuer') or '-'}</td></tr>",
                f"<tr><td {th}>起始時間</td><td {td}>{fmt_dt(cert_info.get('not_before'))}</td></tr>",
                f"<tr><td {th}>過期時間</td><td {td}>{fmt_dt(cert_info.get('not_after'))}</td></tr>",
                f"<tr><td {th}>OCSP 回應</td><td {td}>{ocsp_msg}</td></tr>",
                "</tbody></table>",
            ])

            # 卡片結束
            html_parts.append("</div>")

        html_parts.extend([
            "<hr>",
            "<p style='color:#666; font-size:12px;'>此為自動檢查郵件，請勿直接回覆。</p>",
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
