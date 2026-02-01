"""Генератор Prometheus метрик."""
import os
import time
from urllib.parse import urlparse
from typing import Dict
from utils.template_loader import TemplateLoader


class PrometheusMetrics:
    """Класс для работы с Prometheus метриками."""
    
    @staticmethod
    def generate_metrics(audit_result: Dict) -> str:
        """Генерирует метрики в формате Prometheus."""
        # Извлекаем hostname из URL
        parsed_url = urlparse(audit_result['nexus_url'])
        nexus_hostname = parsed_url.hostname or 'unknown'
        
        summary = audit_result['summary']
        grouped = audit_result.get('grouped_summary', {})
        
        # Подготавливаем данные для шаблона
        context = {
            'nexus_hostname': nexus_hostname,
            'nexus_url': audit_result['nexus_url'],
            'scan_duration': audit_result['scan_duration'],
            'total': summary.get('total', 0),
            'anonymous_access': summary.get('anonymous_access', 0),
            'vulnerable': summary.get('vulnerable', 0),
            'exceptions': summary.get('exceptions', 0),
            'errors': summary.get('errors', 0),
            'last_scan_timestamp': int(time.time()),
        }
        
        # Генерируем базовые метрики из шаблона
        metrics = TemplateLoader.load_template('metrics.prom', context)
        
        # Добавляем метрики по форматам
        for format_name, stats in grouped.get('by_format', {}).items():
            metrics += f'\n# HELP nexus_audit_by_format_total Repositories by format {format_name}'
            metrics += f'\n# TYPE nexus_audit_by_format_total gauge'
            metrics += f'\nnexus_audit_by_format_total{{nexus="{nexus_hostname}",format="{format_name}"}} {stats.get("total", 0)}'
            
            metrics += f'\nnexus_audit_by_format_anonymous{{nexus="{nexus_hostname}",format="{format_name}"}} {stats.get("anonymous_access", 0)}'
            metrics += f'\nnexus_audit_by_format_vulnerable{{nexus="{nexus_hostname}",format="{format_name}"}} {stats.get("vulnerable", 0)}'
        
        # Добавляем метрики по типам репозиториев
        for repo_type, stats in grouped.get('by_type', {}).items():
            metrics += f'\n# HELP nexus_audit_by_type_total Repositories by type {repo_type}'
            metrics += f'\n# TYPE nexus_audit_by_type_total gauge'
            metrics += f'\nnexus_audit_by_type_total{{nexus="{nexus_hostname}",type="{repo_type}"}} {stats.get("total", 0)}'
            
            metrics += f'\nnexus_audit_by_type_anonymous{{nexus="{nexus_hostname}",type="{repo_type}"}} {stats.get("anonymous_access", 0)}'
            metrics += f'\nnexus_audit_by_type_vulnerable{{nexus="{nexus_hostname}",type="{repo_type}"}} {stats.get("vulnerable", 0)}'
        
        # Добавляем метрики по репозиториям
        metrics += '\n# HELP nexus_repository_anonymous_access Repository anonymous access status (1=enabled, 0=disabled)'
        metrics += '\n# TYPE nexus_repository_anonymous_access gauge'
        metrics += '\n# HELP nexus_repository_vulnerable Repository vulnerable status (1=vulnerable, 0=not_vulnerable)'
        metrics += '\n# TYPE nexus_repository_vulnerable gauge'
        
        for repo in audit_result['repositories']:
            repo_name = repo.get('name', 'unknown').replace('"', '\\"')
            repo_format = repo.get('format', 'unknown')
            repo_type = repo.get('type', 'unknown')
            
            access_value = 1 if repo.get('anonymous_access') else 0
            vulnerable_value = 1 if repo.get('is_vulnerable') else 0
            
            metrics += f'\nnexus_repository_anonymous_access{{nexus="{nexus_hostname}",repository="{repo_name}",format="{repo_format}",type="{repo_type}"}} {access_value}'
            metrics += f'\nnexus_repository_vulnerable{{nexus="{nexus_hostname}",repository="{repo_name}",format="{repo_format}",type="{repo_type}"}} {vulnerable_value}'
        
        return metrics
    
    @staticmethod
    def save_metrics(audit_result: Dict, config: Dict) -> str:
        """
        Сохраняет метрики в файл.
        
        Returns:
            Путь к сохраненному файлу
        """
        prometheus_config = config.get('prometheus', {})
        output_dir = prometheus_config.get('output_dir', 'reports')
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Генерируем метрики
        metrics = PrometheusMetrics.generate_metrics(audit_result)
        
        # Сохраняем в файл
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # prom_file = os.path.join(output_dir, f"nexus_metrics_{timestamp}.prom")
        prom_file = os.path.join(output_dir, f"nexus_metrics.prom")
        
        with open(prom_file, 'w', encoding='utf-8') as f:
            f.write(metrics)
        
        return prom_file
