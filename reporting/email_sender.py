"""Отправщик email отчетов."""
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Dict, List


class EmailSender:
    """Класс для отправки email отчетов."""
    
    @staticmethod
    def send_report(audit_result: Dict, config: Dict, json_file_path: str = None) -> bool:
        """
        Отправляет отчет по email.
        
        Args:
            audit_result: Результаты аудита
            config: Конфигурация
            json_file_path: Путь к JSON файлу
            
        Returns:
            True если отправка успешна
        """
        email_config = config.get('email', {})
        recipients = email_config.get('recipients', [])
        
        if not recipients:
            return False
        
        try:
            # Создаем сообщение
            msg = MIMEMultipart()
            msg['From'] = email_config.get('sender', 'nexus-audit@localhost')
            msg['To'] = ', '.join(recipients)
            
            # Тема письма
            subject = EmailSender._create_subject(audit_result, config)
            msg['Subject'] = subject
            
            # Текст письма
            text_body = EmailSender._create_email_body(audit_result)
            msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
            
            # JSON вложение
            if email_config.get('send_json_attachment', True):
                if json_file_path and os.path.exists(json_file_path):
                    with open(json_file_path, 'rb') as f:
                        json_data = f.read()
                else:
                    import json
                    json_data = json.dumps(audit_result, indent=2, ensure_ascii=False, default=str).encode('utf-8')
                
                json_part = MIMEApplication(json_data, Name='nexus_audit_report.json')
                json_part['Content-Disposition'] = 'attachment; filename="nexus_audit_report.json"'
                msg.attach(json_part)
            
            # Отправка
            smtp_server = email_config.get('smtp_server', 'localhost')
            smtp_port = email_config.get('smtp_port', 25)
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Ошибка отправки email: {e}")
            return False
    
    @staticmethod
    def _create_subject(audit_result: Dict, config: Dict) -> str:
        """Создает тему письма."""
        summary = audit_result['summary']
        
        if summary['vulnerable'] > 0:
            return f"[Nexus Audit] ⚠️ Уязвимости: {summary['vulnerable']} - {audit_result['nexus_url']}"
        else:
            return f"[Nexus Audit] ✅ Безопасно - {audit_result['nexus_url']}"
    
    @staticmethod
    def _create_email_body(audit_result: Dict) -> str:
        """Создает тело письма."""
        summary = audit_result['summary']
        
        # Форматируем длительность
        scan_duration_formatted = f"{audit_result['scan_duration']:.2f}"
        
        body = f"""Результаты аудита безопасности Nexus

📊 Сводка:
- Nexus URL: {audit_result['nexus_url']}
- Время проверки: {audit_result['timestamp']}
- Длительность: {scan_duration_formatted} сек.

📈 Статистика:
- Всего репозиториев: {summary['total']}
- С анонимным доступом: {summary['anonymous_access']}
- Уязвимых: {summary['vulnerable']}
- Исключений: {summary['exceptions']}
- Ошибок проверки: {summary['errors']}

"""
        
        if summary['vulnerable'] > 0:
            body += f"\n🚨 ВНИМАНИЕ: Обнаружено {summary['vulnerable']} уязвимых репозиториев!\n"
            body += "Требуется немедленное внимание!\n"
        
        body += f"\nПодробный отчет во вложении: nexus_audit_report.json"
        
        return body
