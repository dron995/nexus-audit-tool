#!/usr/bin/env python3
"""
Оптимизированный Nexus Auditor с вынесенными шаблонами.
"""

import os
import sys
import json
import argparse
import logging
from typing import Dict

# Добавляем путь к модулям проекта
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config_loader import ConfigLoader
from utils.ssl_handler import SSLHandler
from core.auditor import NexusAuditor
from core.models import AuditResult
from reporting.reports import ReportGenerator
from reporting.email_sender import EmailSender
from reporting.prometheus import PrometheusMetrics

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nexus_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def main():
    """Основная функция."""
    parser = argparse.ArgumentParser(
        description='Аудит безопасности Nexus репозиториев',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Конфигурация
    parser.add_argument('--config', default='config/config.yaml',
                       help='Путь к YAML файлу конфигурации (по умолчанию: config/config.yaml)')
    
    # Параметры Nexus
    parser.add_argument('--nexus-url', help='URL Nexus сервера')
    parser.add_argument('--username', help='Имя пользователя Nexus')
    parser.add_argument('--password', help='Пароль Nexus')
    
    # Параметры аудита
    parser.add_argument('--exceptions-file', help='Файл с исключениями')
    parser.add_argument('--repo-types', nargs='+', 
                       choices=['hosted', 'proxy', 'group', 'all'],
                       help='Типы репозиториев для проверки')
    parser.add_argument('--max-workers', type=int, help='Количество потоков')
    
    # SSL настройки
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Отключить проверку SSL сертификатов')
    parser.add_argument('--ca-bundle', 
                       help='Путь к CA bundle файлу')
    
    # Отчетность
    parser.add_argument('--save-reports', action='store_true',
                       help='Сохранить отчеты в файлы')
    parser.add_argument('--output-dir', help='Директория для сохранения отчетов')
    
    # Prometheus метрики
    parser.add_argument('--prometheus', action='store_true',
                       help='Генерировать Prometheus метрики')
    parser.add_argument('--prometheus-output-dir', 
                       help='Директория для сохранения Prometheus метрик')
    
    # Email отправка
    parser.add_argument('--email', nargs='+',
                       help='Email адреса получателей')
    parser.add_argument('--email-sender', 
                       help='Email отправителя')
    parser.add_argument('--smtp-server', default='localhost',
                       help='SMTP сервер')
    parser.add_argument('--smtp-port', type=int, default=25,
                       help='SMTP порт')
    parser.add_argument('--send-email', action='store_true',
                       help='Отправить отчет по email')
    
    # Режим отладки
    parser.add_argument('--debug', action='store_true',
                       help='Включить режим отладки')
    
    args = parser.parse_args()
    
    try:
        # Настройка уровня логирования
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Режим отладки включен")
        
        # Загрузка конфигурации
        config = ConfigLoader.load_config(args.config)
        
        # Переопределение параметрами командной строки
        config = ConfigLoader.override_config(config, args)
        
        # Проверка обязательных параметров
        if not config.get('nexus_url'):
            logger.error("Не указан URL Nexus.")
            parser.print_help()
            sys.exit(1)
        
        # Настройка SSL
        SSLHandler.setup_ssl_context(config)
        
        # Запуск аудита
        auditor = NexusAuditor(config)
        logger.info(f"Запуск аудита для {config['nexus_url']}")
        audit_result = auditor.run_audit()
        
        # Проверка на наличие ошибок (теперь audit_result - объект, проверяем его атрибуты)
        if audit_result.error:
            logger.error(f"Ошибка при выполнении аудита: {audit_result.error}")
            sys.exit(2)
        
        # Преобразуем результат в словарь для совместимости с существующим кодом
        audit_result_dict = audit_result.to_dict()
        
        # Вывод сводки в консоль
        _print_summary(audit_result_dict)
        
        # Сохранение отчетов
        saved_files = {}
        if args.save_reports or config.get('save_reports', False):
            saved_files = ReportGenerator.save_all_reports(audit_result_dict, config)
            logger.info("Отчеты сохранены успешно")
        
        # Отправка email отчета
        if config.get('email', {}).get('enabled'):
            EmailSender.send_report(audit_result_dict, config, saved_files.get('json'))
            logger.info("Email отчет отправлен")
        
        # Генерация Prometheus метрик
        if config.get('prometheus', {}).get('enabled'):
            prometheus_file = PrometheusMetrics.save_metrics(audit_result_dict, config)
            logger.info(f"Prometheus метрики сохранены в {prometheus_file}")
        
        # Код возврата
        if audit_result.summary['vulnerable'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.info("Аудит прерван пользователем")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(2)


def _print_summary(audit_result: dict):
    """Вывод сводки в консоль."""
    summary = audit_result['summary']
    
    # Форматируем длительность
    scan_duration_formatted = f"{audit_result['scan_duration']:.2f}"
    
    print("\n" + "="*60)
    print("СВОДКА АУДИТА")
    print("="*60)
    print(f"Nexus URL: {audit_result['nexus_url']}")
    print(f"Время проверки: {audit_result['timestamp']}")
    print(f"Всего репозиториев: {summary['total']}")
    print(f"С анонимным доступом: {summary['anonymous_access']}")
    print(f"Исключений: {summary['exceptions']}")
    print(f"Уязвимых: {summary['vulnerable']}")
    print(f"Ошибок проверки: {summary['errors']}")
    print(f"Длительность: {scan_duration_formatted} сек.")
    
    if summary['vulnerable'] > 0:
        print(f"\n🚨 ВНИМАНИЕ: Обнаружено {summary['vulnerable']} уязвимых репозиториев!")
        grouped = audit_result.get('grouped_summary', {})
        for repo in grouped.get('vulnerable_repositories', []):
            print(f"  • {repo['name']} ({repo['format']}/{repo['type']})")


if __name__ == "__main__":
    main()
