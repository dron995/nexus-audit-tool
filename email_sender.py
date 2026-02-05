#!/usr/bin/env python3
"""
Email Sender Module
Отправка результатов аудита по электронной почте через SMTP localhost:25
"""

import logging
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from typing import List, Dict, Optional, Tuple
import json
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailSender:
    """Класс для отправки email уведомлений"""
    
    def __init__(self, config: Dict):
        """Инициализация отправителя email"""
        self.config = config
        
        # Настройки SMTP
        self.smtp_host = self.config.get('smtp_host', 'localhost')
        self.smtp_port = self.config.get('smtp_port', 25)
        self.smtp_timeout = self.config.get('smtp_timeout', 10)
        
        # Настройки отправителя и получателя
        self.from_email = self.config.get('from_email', 'nexus-auditor@localhost')
        self.to_emails = self.config.get('to_emails', [])
        self.subject_prefix = self.config.get('subject_prefix', '[Nexus Audit]')
        
        # Настройки email
        self.enabled = self.config.get('enabled', False)
        
        if self.enabled:
            logger.info(f"Email notifications enabled: {self.from_email} -> {self.to_emails}")
            logger.info(f"SMTP server: {self.smtp_host}:{self.smtp_port}")
    
    def _create_email_content(self, summary: Dict, results: List[Dict], 
                            nexus_url: str, console_output: str) -> Tuple[str, str]:
        """Создание текстового и HTML содержимого письма"""
        
        # Текстовое содержимое
        text_content = f"""NEXUS REPOSITORY AUDIT REPORT
{'='*60}

Nexus URL: {nexus_url}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
{'='*60}
Total repositories: {summary['total_repositories']}
Checked: {summary['checked']}
Vulnerable (public access): {summary['vulnerable']}
Secure: {summary['secure']}
Requires manual check: {summary['requires_manual_check']}
Errors: {summary['errors']}
{'='*60}

"""

        if summary['vulnerable'] > 0:
            text_content += "\n⚠️  VULNERABLE REPOSITORIES (PUBLIC ACCESS):\n"
            vulnerable_repos = [r for r in results if r['vulnerable']]
            for vuln in vulnerable_repos:
                text_content += f"\n  • {vuln['repository']}\n"
                text_content += f"    Type: {vuln['type']}, Format: {vuln['format']}\n"
                text_content += f"    URL: {vuln['url']}\n"
                text_content += f"    Details: {vuln['details']}\n"
        
        if summary['errors'] > 0:
            text_content += f"\n\n⚠️  Repositories with errors: {summary['errors']}\n"
            error_repos = [r for r in results if r['status'] in ['ssl_error', 'request_error', 'connection_error', 'timeout']]
            for err in error_repos[:5]:
                text_content += f"  • {err['repository']}: {err['status']} - {err['details']}\n"
            if len(error_repos) > 5:
                text_content += f"  ... and {len(error_repos) - 5} more\n"
        
        text_content += f"\n\nDetailed console output:\n{'='*60}\n{console_output}"
        
        # HTML содержимое
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Nexus Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .summary {{ background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .vulnerable {{ background-color: #ffe6e6; padding: 15px; border-radius: 5px; border-left: 4px solid #ff4444; margin: 15px 0; }}
        .secure {{ background-color: #e6ffe6; padding: 15px; border-radius: 5px; border-left: 4px solid #44cc44; margin: 15px 0; }}
        .errors {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; margin: 15px 0; }}
        .repo-item {{ margin: 10px 0; padding: 10px; background-color: #fff; border: 1px solid #ddd; border-radius: 3px; }}
        .status-vulnerable {{ color: #d9534f; font-weight: bold; }}
        .status-secure {{ color: #5cb85c; font-weight: bold; }}
        .status-error {{ color: #f0ad4e; font-weight: bold; }}
        .metrics {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .console {{ background-color: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; overflow-x: auto; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Nexus Repository Audit Report</h1>
        <p><strong>Nexus URL:</strong> {nexus_url}</p>
        <p><strong>Audit Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>Total repositories</td>
                <td>{summary['total_repositories']}</td>
                <td>📋</td>
            </tr>
            <tr>
                <td>Checked repositories</td>
                <td>{summary['checked']}</td>
                <td>✅</td>
            </tr>
            <tr>
                <td>Vulnerable repositories</td>
                <td>{summary['vulnerable']}</td>
                <td class="status-vulnerable">{'❌ CRITICAL' if summary['vulnerable'] > 0 else '✅ OK'}</td>
            </tr>
            <tr>
                <td>Secure repositories</td>
                <td>{summary['secure']}</td>
                <td class="status-secure">✅</td>
            </tr>
            <tr>
                <td>Requires manual check</td>
                <td>{summary['requires_manual_check']}</td>
                <td>⚠️</td>
            </tr>
            <tr>
                <td>Errors</td>
                <td>{summary['errors']}</td>
                <td class="status-error">{'⚠️ WARNING' if summary['errors'] > 0 else '✅ OK'}</td>
            </tr>
        </table>
        
        <h3>Overall Status:</h3>
        <p>
"""
        
        if summary['vulnerable'] > 0:
            html_content += """            <span style="color: #d9534f; font-weight: bold; font-size: 18px;">
                ⚠️ AUDIT FAILED: Found repositories with public access
            </span>"""
        elif summary['errors'] > summary['checked'] / 2:
            html_content += """            <span style="color: #f0ad4e; font-weight: bold; font-size: 18px;">
                ⚠️ Audit completed with many errors
            </span>"""
        else:
            html_content += """            <span style="color: #5cb85c; font-weight: bold; font-size: 18px;">
                ✅ Audit PASSED: No public access found
            </span>"""
        
        html_content += """
        </p>
    </div>
"""
        
        # Уязвимые репозитории
        if summary['vulnerable'] > 0:
            vulnerable_repos = [r for r in results if r['vulnerable']]
            html_content += """
    <div class="vulnerable">
        <h2>⚠️ Vulnerable Repositories (Public Access)</h2>
"""
            for vuln in vulnerable_repos:
                html_content += f"""
        <div class="repo-item">
            <h3>• {vuln['repository']}</h3>
            <p><strong>Type:</strong> {vuln['type']}</p>
            <p><strong>Format:</strong> {vuln['format']}</p>
            <p><strong>URL:</strong> <a href="{vuln['url']}">{vuln['url']}</a></p>
            <p><strong>Details:</strong> {vuln['details']}</p>
        </div>
"""
            html_content += """
    </div>
"""
        
        # Репозитории с ошибками
        if summary['errors'] > 0:
            error_repos = [r for r in results if r['status'] in ['ssl_error', 'request_error', 'connection_error', 'timeout']]
            html_content += """
    <div class="errors">
        <h2>⚠️ Repositories with Errors</h2>
"""
            for err in error_repos[:10]:
                html_content += f"""
        <div class="repo-item">
            <p><strong>{err['repository']}</strong>: <span class="status-error">{err['status']}</span></p>
            <p><em>{err['details']}</em></p>
        </div>
"""
            if len(error_repos) > 10:
                html_content += f"""
        <p>... and {len(error_repos) - 10} more</p>
"""
            html_content += """
    </div>
"""
        
        # Статистика по типам и форматам
        type_counts = {}
        format_counts = {}
        for result in results:
            repo_type = result['type']
            repo_format = result['format']
            
            if repo_type not in type_counts:
                type_counts[repo_type] = {'total': 0, 'vulnerable': 0}
            type_counts[repo_type]['total'] += 1
            if result['vulnerable']:
                type_counts[repo_type]['vulnerable'] += 1
            
            if repo_format not in format_counts:
                format_counts[repo_format] = {'total': 0, 'vulnerable': 0}
            format_counts[repo_format]['total'] += 1
            if result['vulnerable']:
                format_counts[repo_format]['vulnerable'] += 1
        
        if type_counts:
            html_content += """
    <div class="metrics">
        <h2>📈 Statistics by Repository Type</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Total</th>
                <th>Vulnerable</th>
                <th>Secure</th>
                <th>Vulnerability %</th>
            </tr>
"""
            for repo_type, counts in sorted(type_counts.items()):
                secure_count = counts['total'] - counts['vulnerable']
                vuln_percent = (counts['vulnerable'] / counts['total'] * 100) if counts['total'] > 0 else 0
                html_content += f"""
            <tr>
                <td>{repo_type}</td>
                <td>{counts['total']}</td>
                <td class="status-vulnerable">{counts['vulnerable']}</td>
                <td class="status-secure">{secure_count}</td>
                <td>{vuln_percent:.1f}%</td>
            </tr>
"""
            html_content += """
        </table>
    </div>
"""
        
        if format_counts:
            html_content += """
    <div class="metrics">
        <h2>📈 Statistics by Repository Format</h2>
        <table>
            <tr>
                <th>Format</th>
                <th>Total</th>
                <th>Vulnerable</th>
                <th>Secure</th>
                <th>Vulnerability %</th>
            </tr>
"""
            for repo_format, counts in sorted(format_counts.items()):
                secure_count = counts['total'] - counts['vulnerable']
                vuln_percent = (counts['vulnerable'] / counts['total'] * 100) if counts['total'] > 0 else 0
                html_content += f"""
            <tr>
                <td>{repo_format}</td>
                <td>{counts['total']}</td>
                <td class="status-vulnerable">{counts['vulnerable']}</td>
                <td class="status-secure">{secure_count}</td>
                <td>{vuln_percent:.1f}%</td>
            </tr>
"""
            html_content += """
        </table>
    </div>
"""
        
        # Консольный вывод
        html_content += f"""
    <div class="console">
        <h2>📋 Detailed Console Output</h2>
        <pre>{console_output}</pre>
    </div>
    
    <div style="margin-top: 30px; padding-top: 15px; border-top: 1px solid #ddd; color: #666; font-size: 12px;">
        <p>This email was automatically generated by Nexus Repository Audit Tool.</p>
        <p>Audit completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>
"""
        
        return text_content, html_content
    
    def _create_email_message(self, summary: Dict, results: List[Dict], 
                            nexus_url: str, console_output: str) -> MIMEMultipart:
        """Создание MIME сообщения"""
        text_content, html_content = self._create_email_content(
            summary, results, nexus_url, console_output
        )
        
        # Определяем тему письма в зависимости от результатов
        if summary['vulnerable'] > 0:
            subject = f"{self.subject_prefix} ⚠️ CRITICAL: {summary['vulnerable']} repositories with public access"
        elif summary['errors'] > summary['checked'] / 2:
            subject = f"{self.subject_prefix} ⚠️ WARNING: Audit completed with {summary['errors']} errors"
        else:
            subject = f"{self.subject_prefix} ✅ SUCCESS: No public access found"
        
        # Создаем MIME сообщение
        msg = MIMEMultipart('alternative')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = self.from_email
        msg['To'] = ', '.join(self.to_emails)
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        
        # Добавляем текстовую и HTML версии
        msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
        msg.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        return msg
    
    def send_report(self, summary: Dict, results: List[Dict], 
                   nexus_url: str, console_output: str) -> bool:
        """Отправка отчета по email"""
        
        if not self.enabled:
            logger.debug("Email notifications are disabled")
            return False
        
        if not self.to_emails:
            logger.warning("No email recipients configured")
            return False
        
        try:
            # Создаем email сообщение
            msg = self._create_email_message(summary, results, nexus_url, console_output)
            
            # Подключаемся к SMTP серверу
            logger.info(f"Connecting to SMTP server {self.smtp_host}:{self.smtp_port}")
            
            with smtplib.SMTP(
                host=self.smtp_host,
                port=self.smtp_port,
                timeout=self.smtp_timeout
            ) as server:
                # Не используем starttls() - отправка без TLS/SSL
                # Не используем login() - отправка без аутентификации
                
                # Отправляем email
                server.sendmail(
                    self.from_email,
                    self.to_emails,
                    msg.as_string()
                )
                
                logger.info(f"Email report sent successfully to {len(self.to_emails)} recipients")
                logger.debug(f"Email recipients: {', '.join(self.to_emails)}")
                
                return True
                
        except socket.timeout:
            logger.error(f"SMTP connection timeout to {self.smtp_host}:{self.smtp_port}")
            return False
        except ConnectionRefusedError:
            logger.error(f"SMTP connection refused to {self.smtp_host}:{self.smtp_port}")
            return False
        except socket.gaierror as e:
            logger.error(f"SMTP host resolution error: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email: {e}")
            return False
    
    def send_test_email(self) -> bool:
        """Отправка тестового email для проверки конфигурации"""
        if not self.enabled:
            logger.warning("Email notifications are disabled")
            return False
        
        test_summary = {
            'total_repositories': 25,
            'checked': 20,
            'vulnerable': 2,
            'secure': 15,
            'requires_manual_check': 3,
            'errors': 0
        }
        
        test_results = [
            {
                'repository': 'maven-releases',
                'type': 'maven2-hosted',
                'format': 'maven2',
                'url': 'https://nexus.example.com/repository/maven-releases/',
                'status': 'secure',
                'vulnerable': False,
                'details': 'Access requires authentication'
            },
            {
                'repository': 'docker-public',
                'type': 'docker-proxy',
                'format': 'docker',
                'url': 'https://nexus.example.com/repository/docker-public/',
                'status': 'vulnerable',
                'vulnerable': True,
                'details': 'Public access without authentication'
            }
        ]
        
        test_console_output = """=== TEST EMAIL ===
This is a test email to verify email configuration.
If you receive this email, email notifications are working correctly.
"""
        
        logger.info("Sending test email...")
        
        success = self.send_report(
            test_summary,
            test_results,
            "https://nexus.example.com",
            test_console_output
        )
        
        if success:
            logger.info("Test email sent successfully")
        else:
            logger.error("Failed to send test email")
        
        return success


def parse_email_list(email_string: str) -> List[str]:
    """Парсинг списка email адресов"""
    if not email_string:
        return []
    
    emails = []
    for email in email_string.split(','):
        email = email.strip()
        if email and '@' in email:
            emails.append(email)
    
    return emails
