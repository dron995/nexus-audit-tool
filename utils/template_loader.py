"""Загрузчик шаблонов."""
import os
import re
from typing import Dict, Any


class TemplateLoader:
    """Класс для загрузки шаблонов из файлов."""
    
    TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    
    @staticmethod
    def load_template(template_name: str, context: Dict[str, Any] = None) -> str:
        """
        Загружает шаблон из файла и заполняет его данными.
        
        Args:
            template_name: Имя файла шаблона
            context: Словарь с данными для заполнения
            
        Returns:
            Заполненный шаблон
        """
        template_path = os.path.join(TemplateLoader.TEMPLATES_DIR, template_name)
        
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
            
            if context:
                template = TemplateLoader._fill_template_safe(template, context)
            
            return template
            
        except FileNotFoundError:
            # Возвращаем простой шаблон по умолчанию
            return TemplateLoader._get_default_template(template_name, context)
        except Exception as e:
            raise Exception(f"Ошибка загрузки шаблона {template_name}: {e}")
    
    @staticmethod
    def _fill_template_safe(template: str, context: Dict[str, Any]) -> str:
        """Безопасно заполняет шаблон данными, используя регулярные выражения."""
        # Ищем только конкретные переменные в формате {variable}
        # Обрабатываем также простые форматирования {variable:.2f}
        pattern = r'\{(\w+)(?::\.[^}]+)?\}'
        
        def replace_match(match):
            full_match = match.group(0)
            key = match.group(1)
            
            if key in context:
                value = context[key]
                # Если значение уже строка (предварительно отформатированное)
                if isinstance(value, str):
                    return value
                # Для чисел и других типов
                else:
                    return str(value)
            else:
                # Если переменной нет в контексте, оставляем как есть
                return full_match
        
        return re.sub(pattern, replace_match, template)
    
    @staticmethod
    def _get_default_template(template_name: str, context: Dict[str, Any] = None) -> str:
        """Возвращает простой шаблон по умолчанию."""
        if template_name == 'report.html':
            # Простой HTML шаблон без сложного CSS
            simple_html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Отчет аудита Nexus</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Отчет аудита Nexus</h1>
        <p><strong>Nexus URL:</strong> {nexus_url}</p>
        <p><strong>Время проверки:</strong> {timestamp}</p>
    </div>
    
    <div>
        <h2>Сводка</h2>
        <p>Всего репозиториев: {total}</p>
        <p>С анонимным доступом: {anonymous_access}</p>
        <p>Исключений: {exceptions}</p>
        <p>Уязвимых: {vulnerable}</p>
    </div>
    
    <h2>Детали по репозиториям</h2>
    <table>
        <thead>
            <tr>
                <th>Репозиторий</th>
                <th>Тип</th>
                <th>Формат</th>
                <th>Анонимный доступ</th>
                <th>Статус</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""
            return TemplateLoader._fill_template_safe(simple_html, context)
            
        elif template_name == 'email.txt':
            simple_text = """Результаты аудита Nexus:
URL: {nexus_url}
Время: {timestamp}
Всего репозиториев: {total}
Уязвимых: {vulnerable}"""
            return TemplateLoader._fill_template_safe(simple_text, context)
            
        elif template_name == 'metrics.prom':
            simple_metrics = """# HELP nexus_audit_info Information about Nexus audit
# TYPE nexus_audit_info gauge
nexus_audit_info{{nexus="{nexus_hostname}"}} 1
# HELP nexus_audit_repositories_total Total number of repositories
# TYPE nexus_audit_repositories_total gauge
nexus_audit_repositories_total{{nexus="{nexus_hostname}"}} {total}"""
            return TemplateLoader._fill_template_safe(simple_metrics, context)
            
        else:
            return "Шаблон не найден"
    
    @staticmethod
    def get_template_names() -> list:
        """Возвращает список доступных шаблонов."""
        if os.path.exists(TemplateLoader.TEMPLATES_DIR):
            return [f for f in os.listdir(TemplateLoader.TEMPLATES_DIR) 
                   if f.endswith(('.html', '.txt', '.prom', '.md'))]
        return []
