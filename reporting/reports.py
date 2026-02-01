"""Генератор отчетов."""
import os
import json
from datetime import datetime
from typing import Dict
from utils.template_loader import TemplateLoader


class ReportGenerator:
    """Класс для генерации отчетов."""
    
    @staticmethod
    def generate_html_report(audit_result: Dict) -> str:
        """Генерирует HTML отчет."""
        summary = audit_result['summary']
        
        # Определяем класс для карточки уязвимостей
        vulnerable_class = "danger" if summary.get('vulnerable', 0) > 0 else ""
        
        # Форматируем значения
        scan_duration_formatted = f"{audit_result.get('scan_duration', 0):.2f}"
        
        context = {
            'nexus_url': audit_result.get('nexus_url', 'Unknown'),
            'timestamp': audit_result.get('timestamp', 'Unknown'),
            'scan_duration': scan_duration_formatted,  # Уже отформатированное значение
            'total': summary.get('total', 0),
            'anonymous_access': summary.get('anonymous_access', 0),
            'exceptions': summary.get('exceptions', 0),
            'vulnerable': summary.get('vulnerable', 0),
            'vulnerable_class': vulnerable_class,
            'rows': ReportGenerator._generate_html_rows(audit_result)
        }
        
        return TemplateLoader.load_template('report.html', context)
    
    @staticmethod
    def _generate_html_rows(audit_result: Dict) -> str:
        """Генерирует строки HTML таблицы."""
        rows = []
        repositories = audit_result.get('repositories', [])
        
        for repo in repositories:
            # Безопасное получение значений
            repo_name = repo.get('name', 'Unknown')
            repo_type = repo.get('type', 'unknown')
            repo_format = repo.get('format', 'unknown')
            anonymous_access = repo.get('anonymous_access', False)
            status_code = repo.get('status_code', 'N/A')
            is_exception = repo.get('is_exception', False)
            error = repo.get('error')
            is_vulnerable = repo.get('is_vulnerable', False)
            
            # Определяем статус
            if is_vulnerable:
                status = "УЯЗВИМЫЙ"
                row_class = "vulnerable"
            elif is_exception:
                status = "Исключение"
                row_class = ""
            elif error:
                status = f"Ошибка: {error[:30]}..." if error else "Ошибка"
                row_class = "error"
            elif anonymous_access:
                status = "Анонимный доступ"
                row_class = ""
            else:
                status = "Защищен"
                row_class = ""
            
            rows.append(f"""
            <tr class="{row_class}">
                <td>{repo_name}</td>
                <td>{repo_type}</td>
                <td>{repo_format}</td>
                <td>{'Да' if anonymous_access else 'Нет'}</td>
                <td>{status_code}</td>
                <td>{'Да' if is_exception else 'Нет'}</td>
                <td>{status}</td>
            </tr>
            """)
        
        return ''.join(rows)
    
    @staticmethod
    def generate_text_report(audit_result: Dict) -> str:
        """Генерирует текстовый отчет."""
        summary = audit_result.get('summary', {})
        vulnerable = summary.get('vulnerable', 0)
        
        vulnerable_text = ""
        if vulnerable > 0:
            vulnerable_text = f"\n🚨 ВНИМАНИЕ: Обнаружено {vulnerable} уязвимых репозиториев!\nТребуется немедленное внимание!\n"
        
        # Форматируем значения
        scan_duration_formatted = f"{audit_result.get('scan_duration', 0):.2f}"
        
        context = {
            'nexus_url': audit_result.get('nexus_url', 'Unknown'),
            'timestamp': audit_result.get('timestamp', 'Unknown'),
            'scan_duration': scan_duration_formatted,  # Уже отформатированное значение
            'total': summary.get('total', 0),
            'anonymous_access': summary.get('anonymous_access', 0),
            'exceptions': summary.get('exceptions', 0),
            'vulnerable': vulnerable,
            'errors': summary.get('errors', 0),
            'vulnerable_text': vulnerable_text
        }
        
        return TemplateLoader.load_template('email.txt', context)
    
    @staticmethod
    def save_all_reports(audit_result: Dict, config: Dict) -> Dict:
        """
        Сохраняет все отчеты в файлы.
        
        Returns:
            Словарь с путями к сохраненным файлам
        """
        output_dir = config.get('output_dir', 'reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        saved_files = {}
        
        # JSON отчет
        json_file = os.path.join(output_dir, f"nexus_audit_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(audit_result, f, indent=2, ensure_ascii=False, default=str)
        saved_files['json'] = json_file
        
        # HTML отчет
        html_report = ReportGenerator.generate_html_report(audit_result)
        html_file = os.path.join(output_dir, f"nexus_audit_{timestamp}.html")
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        saved_files['html'] = html_file
        
        # Текстовый отчет
        text_report = ReportGenerator.generate_text_report(audit_result)
        text_file = os.path.join(output_dir, f"nexus_audit_{timestamp}.txt")
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(text_report)
        saved_files['text'] = text_file
        
        return saved_files
