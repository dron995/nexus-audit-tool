#!/usr/bin/env python3
"""
Nexus Repository Unauthorized Access Auditor
Проверяет наличие публичного доступа к репозиториям Nexus OSS без аутентификации
"""

import argparse
import json
import logging
import sys
import urllib.parse
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import yaml
import requests
from requests.adapters import HTTPAdapter
import ssl
import urllib3
import io

# Импортируем модуль для отправки email
try:
    from email_sender import EmailSender, parse_email_list
    EMAIL_MODULE_AVAILABLE = True
except ImportError:
    EMAIL_MODULE_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Email module not found. Email notifications will be disabled.")

# Отключаем предупреждения urllib3 если проверка SSL отключена
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('nexus_audit.log')
    ]
)
logger = logging.getLogger(__name__)


class PrometheusMetricsExporter:
    """Класс для экспорта метрик в формате Prometheus"""
    
    @staticmethod
    def generate_metrics(summary: Dict, results: List[Dict], 
                        nexus_url: str, timestamp: int = None) -> str:
        """Генерация метрик Prometheus"""
        if timestamp is None:
            timestamp = int(time.time())
        
        # Основные метрики
        metrics_lines = [
            '# HELP nexus_audit_repositories_total Total number of repositories in Nexus',
            '# TYPE nexus_audit_repositories_total gauge',
            f'nexus_audit_repositories_total{{nexus="{nexus_url}"}} {summary["total_repositories"]}',
            '',
            '# HELP nexus_audit_repositories_checked Number of repositories checked',
            '# TYPE nexus_audit_repositories_checked gauge',
            f'nexus_audit_repositories_checked{{nexus="{nexus_url}"}} {summary["checked"]}',
            '',
            '# HELP nexus_audit_repositories_vulnerable Number of repositories with public access',
            '# TYPE nexus_audit_repositories_vulnerable gauge',
            f'nexus_audit_repositories_vulnerable{{nexus="{nexus_url}"}} {summary["vulnerable"]}',
            '',
            '# HELP nexus_audit_repositories_secure Number of repositories requiring authentication',
            '# TYPE nexus_audit_repositories_secure gauge',
            f'nexus_audit_repositories_secure{{nexus="{nexus_url}"}} {summary["secure"]}',
            '',
            '# HELP nexus_audit_repositories_requires_manual_check Number of repositories requiring manual check',
            '# TYPE nexus_audit_repositories_requires_manual_check gauge',
            f'nexus_audit_repositories_requires_manual_check{{nexus="{nexus_url}"}} {summary["requires_manual_check"]}',
            '',
            '# HELP nexus_audit_repositories_errors Number of repositories with check errors',
            '# TYPE nexus_audit_repositories_errors gauge',
            f'nexus_audit_repositories_errors{{nexus="{nexus_url}"}} {summary["errors"]}',
            '',
            '# HELP nexus_audit_repositories_health Health status of audit (0=healthy, 1=unhealthy)',
            '# TYPE nexus_audit_repositories_health gauge',
            f'nexus_audit_repositories_health{{nexus="{nexus_url}"}} {1 if summary["vulnerable"] > 0 else 0}',
            '',
            '# HELP nexus_audit_last_run_timestamp Timestamp of last audit run',
            '# TYPE nexus_audit_last_run_timestamp gauge',
            f'nexus_audit_last_run_timestamp{{nexus="{nexus_url}"}} {timestamp}',
            '',
            '# HELP nexus_audit_repository_status Status of individual repositories',
            '# TYPE nexus_audit_repository_status gauge',
        ]
        
        # Метрики для каждого репозитория
        for result in results:
            repo_name = result['repository'].replace('"', '\\"').replace('\n', ' ')
            repo_type = result['type'].replace('"', '\\"').replace('\n', ' ')
            repo_format = result['format'].replace('"', '\\"').replace('\n', ' ')
            status = result['status']
            
            # Значение метрики в зависимости от статуса
            status_value = {
                'vulnerable': 3,
                'secure': 1,
                'requires_manual_check': 2,
                'special_check': 2,
                'ssl_error': 4,
                'request_error': 4,
                'connection_error': 4,
                'timeout': 4,
                'unexpected': 4,
                'service_unavailable': 4,
                'unknown': 0
            }.get(status, 0)
            
            metrics_lines.append(
                f'nexus_audit_repository_status{{nexus="{nexus_url}",repository="{repo_name}",type="{repo_type}",format="{repo_format}",status="{status}"}} {status_value}'
            )
        
        # Метрики по типам репозиториев
        type_counts = {}
        for result in results:
            repo_type = result['type'].replace('\n', ' ')
            if repo_type not in type_counts:
                type_counts[repo_type] = {'vulnerable': 0, 'total': 0}
            
            type_counts[repo_type]['total'] += 1
            if result['vulnerable']:
                type_counts[repo_type]['vulnerable'] += 1
        
        if type_counts:
            metrics_lines.extend([
                '',
                '# HELP nexus_audit_repositories_by_type_total Total repositories by type',
                '# TYPE nexus_audit_repositories_by_type_total gauge',
                '# HELP nexus_audit_repositories_by_type_vulnerable Vulnerable repositories by type',
                '# TYPE nexus_audit_repositories_by_type_vulnerable gauge',
            ])
            
            for repo_type, counts in type_counts.items():
                repo_type_escaped = repo_type.replace('"', '\\"')
                metrics_lines.append(
                    f'nexus_audit_repositories_by_type_total{{nexus="{nexus_url}",type="{repo_type_escaped}"}} {counts["total"]}'
                )
                metrics_lines.append(
                    f'nexus_audit_repositories_by_type_vulnerable{{nexus="{nexus_url}",type="{repo_type_escaped}"}} {counts["vulnerable"]}'
                )
        
        # Метрики по форматам репозиториев
        format_counts = {}
        for result in results:
            repo_format = result['format'].replace('\n', ' ')
            if repo_format not in format_counts:
                format_counts[repo_format] = {'vulnerable': 0, 'total': 0}
            
            format_counts[repo_format]['total'] += 1
            if result['vulnerable']:
                format_counts[repo_format]['vulnerable'] += 1
        
        if format_counts:
            metrics_lines.extend([
                '',
                '# HELP nexus_audit_repositories_by_format_total Total repositories by format',
                '# TYPE nexus_audit_repositories_by_format_total gauge',
                '# HELP nexus_audit_repositories_by_format_vulnerable Vulnerable repositories by format',
                '# TYPE nexus_audit_repositories_by_format_vulnerable gauge',
            ])
            
            for repo_format, counts in format_counts.items():
                repo_format_escaped = repo_format.replace('"', '\\"')
                metrics_lines.append(
                    f'nexus_audit_repositories_by_format_total{{nexus="{nexus_url}",format="{repo_format_escaped}"}} {counts["total"]}'
                )
                metrics_lines.append(
                    f'nexus_audit_repositories_by_format_vulnerable{{nexus="{nexus_url}",format="{repo_format_escaped}"}} {counts["vulnerable"]}'
                )
        
        # Добавляем пустую строку в конце (требование Prometheus)
        metrics_lines.append('')
        
        return '\n'.join(metrics_lines)
    
    @staticmethod
    def write_metrics_file(metrics_content: str, filepath: str):
        """Запись метрик в файл"""
        try:
            # Создаем директорию если её нет
            filepath_obj = Path(filepath)
            filepath_obj.parent.mkdir(parents=True, exist_ok=True)
            
            # Записываем файл с атомарной заменой
            temp_file = f"{filepath}.tmp"
            with open(temp_file, 'w', encoding='utf-8', newline='\n') as f:
                f.write(metrics_content)
            
            # Атомарно заменяем старый файл новым
            Path(temp_file).replace(filepath)
            
            # Проверяем что файл не пустой
            if Path(filepath).stat().st_size == 0:
                logger.warning(f"Prometheus metrics file is empty: {filepath}")
                return False
            
            logger.info(f"Prometheus metrics saved to: {filepath} ({Path(filepath).stat().st_size} bytes)")
            return True
        except Exception as e:
            logger.error(f"Error saving Prometheus metrics to {filepath}: {e}")
            # Пробуем записать в текущую директорию как fallback
            try:
                fallback_file = f"nexus_metrics_{int(time.time())}.prom"
                with open(fallback_file, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(metrics_content)
                logger.info(f"Prometheus metrics saved to fallback location: {fallback_file}")
                return True
            except Exception as e2:
                logger.error(f"Error saving to fallback location: {e2}")
                return False


class NexusAuditor:
    def __init__(self, config_path: str, 
                 repo_types_override: Optional[List[str]] = None,
                 repo_formats_override: Optional[List[str]] = None,
                 enable_prometheus_override: Optional[bool] = None,
                 prometheus_file_override: Optional[str] = None,
                 enable_email_override: Optional[bool] = None,
                 email_recipients_override: Optional[str] = None):
        """Инициализация аудитора с конфигурацией"""
        self.config = self._load_config(config_path)
        
        # Применяем переопределения из параметров запуска
        self._apply_overrides(repo_types_override, repo_formats_override, 
                            enable_prometheus_override, prometheus_file_override,
                            enable_email_override, email_recipients_override)
        
        # Настройка SSL параметров для ВСЕХ запросов
        self.ssl_verify = self.config['ssl'].get('verify_ssl', True)
        self.ca_cert = self.config['ssl'].get('rootCA')
        self.verify_hostname = self.config['ssl'].get('verify_hostname', True)
        
        # Настройки Prometheus
        self.prometheus_enabled = self.config['prometheus'].get('enabled', False)
        self.prometheus_file = self.config['prometheus'].get('file', 'nexus_audit_metrics.prom')
        
        # Настройки Email
        self.email_enabled = self.config['email'].get('enabled', False)
        
        # Инициализируем отправитель email если модуль доступен
        self.email_sender = None
        if EMAIL_MODULE_AVAILABLE and self.email_enabled:
            self.email_sender = EmailSender(self.config['email'])
        
        # Создаем отдельные сессии для запросов с аутентификацией и без
        self.auth_session = requests.Session()
        self.public_session = requests.Session()
        
        self._configure_sessions()
        self._configure_auth()
        
        # Базовые настройки
        self.base_url = self.config['nexus']['url'].rstrip('/')
        self.excluded_repos = self._load_excluded_repos()
        
        # Инициализируем экспортер метрик
        self.metrics_exporter = PrometheusMetricsExporter()
        
        # Для захвата консольного вывода
        self.console_output = ""
        self._original_stdout = None
        self._capture_buffer = None
        
    def _load_config(self, config_path: str) -> Dict:
        """Загрузка конфигурационного файла"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # Валидация обязательных полей
            required_fields = ['nexus.url', 'nexus.username', 'nexus.password']
            for field in required_fields:
                keys = field.split('.')
                current = config
                for key in keys:
                    if key not in current:
                        raise ValueError(f"Missing required field: {field}")
                    current = current[key]
            
            # Устанавливаем значения по умолчанию для SSL
            if 'ssl' not in config:
                config['ssl'] = {}
            config['ssl'].setdefault('verify_ssl', True)
            config['ssl'].setdefault('verify_hostname', True)
            
            # Устанавливаем значения по умолчанию для аудита
            if 'audit' not in config:
                config['audit'] = {}
            config['audit'].setdefault('repository_types', ['hosted', 'proxy'])
            config['audit'].setdefault('repository_formats', [])
            config['audit'].setdefault('exclude_file', '')
            
            # Устанавливаем значения по умолчанию для Prometheus
            if 'prometheus' not in config:
                config['prometheus'] = {}
            config['prometheus'].setdefault('enabled', False)
            config['prometheus'].setdefault('file', 'nexus_audit_metrics.prom')
            
            # Устанавливаем значения по умолчанию для Email
            if 'email' not in config:
                config['email'] = {}
            config['email'].setdefault('enabled', False)
            config['email'].setdefault('smtp_host', 'localhost')
            config['email'].setdefault('smtp_port', 25)
            config['email'].setdefault('smtp_timeout', 10)
            config['email'].setdefault('from_email', 'nexus-auditor@localhost')
            config['email'].setdefault('to_emails', [])
            config['email'].setdefault('subject_prefix', '[Nexus Audit]')
            
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise
    
    def _apply_overrides(self, repo_types_override: Optional[List[str]], 
                        repo_formats_override: Optional[List[str]],
                        enable_prometheus_override: Optional[bool],
                        prometheus_file_override: Optional[str],
                        enable_email_override: Optional[bool],
                        email_recipients_override: Optional[str]):
        """Применение переопределений из параметров запуска"""
        # Обрабатываем типы репозиториев
        if repo_types_override:
            self.repo_types = repo_types_override
            logger.info(f"Repository types overridden from CLI: {self.repo_types}")
        else:
            self.repo_types = self.config['audit'].get('repository_types', ['hosted', 'proxy'])
            logger.info(f"Repository types from config: {self.repo_types}")
        
        # Обрабатываем форматы репозиториев
        if repo_formats_override is not None:
            # Если передано пустое значение, проверяем все форматы
            if repo_formats_override == []:
                self.repo_formats = []
                logger.info("Repository formats: ALL (empty list from CLI)")
            else:
                self.repo_formats = repo_formats_override
                logger.info(f"Repository formats overridden from CLI: {self.repo_formats}")
        else:
            self.repo_formats = self.config['audit'].get('repository_formats', [])
            if self.repo_formats:
                logger.info(f"Repository formats from config: {self.repo_formats}")
            else:
                logger.info("Repository formats: ALL (empty list from config)")
        
        # Обрабатываем настройки Prometheus
        if enable_prometheus_override is not None:
            self.prometheus_enabled = enable_prometheus_override
            logger.info(f"Prometheus export overridden from CLI: {self.prometheus_enabled}")
        else:
            self.prometheus_enabled = self.config['prometheus'].get('enabled', False)
            logger.info(f"Prometheus export from config: {self.prometheus_enabled}")
        
        if prometheus_file_override:
            self.prometheus_file = prometheus_file_override
            logger.info(f"Prometheus file overridden from CLI: {self.prometheus_file}")
        else:
            self.prometheus_file = self.config['prometheus'].get('file', 'nexus_audit_metrics.prom')
            logger.info(f"Prometheus file from config: {self.prometheus_file}")
        
        # Обрабатываем настройки Email
        if enable_email_override is not None:
            self.email_enabled = enable_email_override
            logger.info(f"Email notifications overridden from CLI: {self.email_enabled}")
        else:
            self.email_enabled = self.config['email'].get('enabled', False)
            logger.info(f"Email notifications from config: {self.email_enabled}")
        
        # Обрабатываем получателей email
        if email_recipients_override:
            if EMAIL_MODULE_AVAILABLE:
                email_list = parse_email_list(email_recipients_override)
                self.config['email']['to_emails'] = email_list
                logger.info(f"Email recipients overridden from CLI: {email_list}")
            else:
                logger.warning("Email module not available, cannot parse email recipients")
        
        # Записываем обратно в конфиг для отчета
        self.config['audit']['repository_types'] = self.repo_types
        self.config['audit']['repository_formats'] = self.repo_formats
        self.config['prometheus']['enabled'] = self.prometheus_enabled
        self.config['prometheus']['file'] = self.prometheus_file
        self.config['email']['enabled'] = self.email_enabled
    
    def _configure_sessions(self):
        """Настройка SSL для всех сессий"""
        if self.ca_cert:
            # Если указан пользовательский CA, используем его для всех сессий
            self.auth_session.verify = self.ca_cert
            self.public_session.verify = self.ca_cert
            
            # Отключаем проверку имени хоста если требуется
            if not self.verify_hostname:
                # Создаем кастомный адаптер для отключения проверки имени хоста
                class NoVerifyHostnameAdapter(HTTPAdapter):
                    def init_poolmanager(self, *args, **kwargs):
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_REQUIRED
                        kwargs['ssl_context'] = context
                        return super().init_poolmanager(*args, **kwargs)
                
                # Монтируем адаптер для всех протоколов
                adapter = NoVerifyHostnameAdapter()
                self.auth_session.mount('https://', adapter)
                self.public_session.mount('https://', adapter)
                
            logger.info(f"SSL configured with custom CA: {self.ca_cert}")
            
        elif not self.ssl_verify:
            # Если проверка SSL отключена
            self.auth_session.verify = False
            self.public_session.verify = False
            logger.warning("SSL verification disabled")
        else:
            # Используем системные CA
            self.auth_session.verify = True
            self.public_session.verify = True
            logger.info("SSL configured with system CA")
    
    def _configure_auth(self):
        """Настройка аутентификации для сессии с аутентификацией"""
        nexus_config = self.config['nexus']
        self.auth = (nexus_config['username'], nexus_config['password'])
    
    def _load_excluded_repos(self) -> List[str]:
        """Загрузка списка исключенных репозиториев"""
        exclude_file = self.config['audit'].get('exclude_file')
        if not exclude_file:
            return []
        
        try:
            exclude_path = Path(exclude_file)
            if exclude_path.exists():
                with open(exclude_path, 'r', encoding='utf-8') as f:
                    repos = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"Loaded {len(repos)} excluded repositories from {exclude_file}")
                return repos
            else:
                logger.warning(f"Exclude file not found: {exclude_file}")
                return []
        except Exception as e:
            logger.error(f"Error loading exclude file: {e}")
            return []
    
    def _start_capture_console(self):
        """Начинаем захват консольного вывода"""
        self._capture_buffer = io.StringIO()
        self._original_stdout = sys.stdout
        sys.stdout = self._capture_buffer
    
    def _stop_capture_console(self):
        """Завершаем захват консольного вывода"""
        if self._capture_buffer and self._original_stdout:
            sys.stdout = self._original_stdout
            self.console_output = self._capture_buffer.getvalue()
            self._capture_buffer.close()
    
    def get_all_repositories(self) -> List[Dict]:
        """Получение списка всех репозиториев через API Nexus"""
        api_url = f"{self.base_url}/service/rest/v1/repositories"
        
        try:
            logger.debug(f"Fetching repositories from: {api_url}")
            response = self.auth_session.get(
                api_url, 
                auth=self.auth, 
                timeout=30,
                headers={'Accept': 'application/json'}
            )
            
            if response.status_code == 401:
                logger.error("Authentication failed. Check username/password.")
                raise ValueError("Authentication failed")
            
            response.raise_for_status()
            repositories = response.json()
            logger.info(f"Retrieved {len(repositories)} repositories")
            return repositories
            
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error when fetching repositories: {e}")
            if self.ca_cert:
                logger.error(f"Check if CA certificate {self.ca_cert} is valid for {self.base_url}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching repositories: {e}")
            raise
    
    def filter_repositories(self, repositories: List[Dict]) -> List[Dict]:
        """Фильтрация репозиториев по типам, форматам и исключениям"""
        filtered = []
        
        for repo in repositories:
            repo_name = repo['name']
            
            # Проверка на исключение
            if repo_name in self.excluded_repos:
                logger.debug(f"Repository {repo_name} excluded from audit")
                continue
            
            # Фильтрация по типу
            repo_type = repo['type']
            type_check = False
            
            # Поддерживаем разные форматы типов:
            # hosted, proxy, group или maven2-hosted, docker-proxy и т.д.
            for target_type in self.repo_types:
                target_type_lower = target_type.lower()
                repo_type_lower = repo_type.lower()
                
                # Проверяем точное совпадение или вхождение
                if (target_type_lower == repo_type_lower or 
                    f"-{target_type_lower}" in repo_type_lower or
                    target_type_lower in repo_type_lower.split('-')):
                    type_check = True
                    break
            
            if not type_check:
                logger.debug(f"Repository {repo_name} type {repo_type} not in {self.repo_types}")
                continue
            
            # Фильтрация по формату
            repo_format = repo.get('format', '').lower()
            if self.repo_formats:  # Если список не пустой
                format_check = False
                for target_format in self.repo_formats:
                    if target_format.lower() == repo_format:
                        format_check = True
                        break
                
                if not format_check:
                    logger.debug(f"Repository {repo_name} format {repo_format} not in {self.repo_formats}")
                    continue
            
            filtered.append(repo)
        
        logger.info(f"Filtered to {len(filtered)} repositories for audit")
        return filtered
    
    def test_repository_access(self, repository: Dict) -> Dict[str, Any]:
        """Проверка доступа к репозиторию без аутентификации"""
        repo_name = repository['name']
        repo_type = repository['type']
        repo_format = repository.get('format', 'unknown')
        
        # Формируем URL для проверки
        test_url = f"{self.base_url}/repository/{urllib.parse.quote(repo_name)}/"
        
        result = {
            'repository': repo_name,
            'type': repo_type,
            'format': repo_format,
            'url': test_url,
            'status': 'unknown',
            'http_status': None,
            'vulnerable': False,
            'details': ''
        }
        
        try:
            logger.debug(f"Testing public access to: {test_url}")
            
            # Пытаемся получить доступ без аутентификации
            response = self.public_session.get(
                test_url,
                allow_redirects=False,
                timeout=15
            )
            
            result['http_status'] = response.status_code
            
            if response.status_code == 200:
                result['status'] = 'vulnerable'
                result['vulnerable'] = True
                result['details'] = 'Public access without authentication'
                logger.warning(f"VULNERABLE: {repo_name} allows public access (HTTP 200)")
            
            elif response.status_code == 403:
                result['status'] = 'secure'
                result['details'] = 'Access requires authentication'
                logger.info(f"SECURE: {repo_name} requires authentication (HTTP 403)")
            
            elif response.status_code == 401:
                result['status'] = 'secure'
                result['details'] = 'Access requires authentication'
                logger.info(f"SECURE: {repo_name} requires authentication (HTTP 401)")
            
            elif response.status_code == 400:
                # Требуется дополнительная проверка
                result = self._perform_additional_check(repository, result)
            
            elif response.status_code == 404:
                result['status'] = 'special_check'
                result['details'] = 'Repository might require specific endpoint access'
                # Пытаемся получить доступ к корневому пути репозитория
                self._check_root_path(repository, result)
            
            elif response.status_code == 502 or response.status_code == 503:
                result['status'] = 'service_unavailable'
                result['details'] = f'Service unavailable (HTTP {response.status_code})'
                logger.warning(f"SERVICE UNAVAILABLE: {repo_name} returned HTTP {response.status_code}")
            
            else:
                result['status'] = 'unexpected'
                result['details'] = f'Unexpected HTTP status: {response.status_code}'
                logger.warning(f"UNEXPECTED: {repo_name} returned HTTP {response.status_code}")
        
        except requests.exceptions.SSLError as e:
            result['status'] = 'ssl_error'
            result['details'] = f'SSL error: {str(e)}'
            logger.error(f"SSL ERROR for {repo_name}: {e}")
        
        except requests.exceptions.ConnectionError as e:
            result['status'] = 'connection_error'
            result['details'] = f'Connection error: {str(e)}'
            logger.error(f"CONNECTION ERROR for {repo_name}: {e}")
        
        except requests.exceptions.Timeout as e:
            result['status'] = 'timeout'
            result['details'] = f'Request timeout: {str(e)}'
            logger.error(f"TIMEOUT for {repo_name}: {e}")
        
        except requests.exceptions.RequestException as e:
            result['status'] = 'request_error'
            result['details'] = f'Request error: {str(e)}'
            logger.error(f"REQUEST ERROR for {repo_name}: {e}")
        
        return result
    
    def _perform_additional_check(self, repository: Dict, result: Dict) -> Dict:
        """Дополнительная проверка для HTTP 400"""
        repo_name = repository['name']
        repo_format = repository.get('format', '').lower()
        
        # Пробуем альтернативные URL в зависимости от формата
        test_urls = []
        
        if repo_format == 'maven2':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/.meta/")
            test_urls.append(f"{self.base_url}/repository/{repo_name}/archetype-catalog.xml")
        elif repo_format == 'docker':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/v2/")
            test_urls.append(f"{self.base_url}/repository/{repo_name}/v2/_catalog")
        elif repo_format == 'npm':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/-/all")
            test_urls.append(f"{self.base_url}/repository/{repo_name}/-/ping")
        elif repo_format == 'nuget':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/index.json")
        elif repo_format == 'pypi':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/simple/")
        elif repo_format == 'apt':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/dists/")
        elif repo_format == 'yum' or repo_format == 'rpm':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/repodata/")
        elif repo_format == 'raw':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/.meta/")
            test_urls.append(f"{self.base_url}/repository/{repo_name}/index.html")
        elif repo_format == 'helm':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/index.yaml")
        elif repo_format == 'bower':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/packages/")
        elif repo_format == 'cocoapods':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/Specs/")
        elif repo_format == 'conan':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/v1/ping")
        elif repo_format == 'conda':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/noarch/repodata.json")
        elif repo_format == 'cran':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/src/contrib/")
        elif repo_format == 'gems':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/specs.4.8.gz")
        elif repo_format == 'gitlfs':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/objects/batch")
        elif repo_format == 'go':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/@v/list")
        elif repo_format == 'p2':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/content.xml")
        elif repo_format == 'rubygems':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/specs.4.8.gz")
        elif repo_format == 'sbt':
            test_urls.append(f"{self.base_url}/repository/{repo_name}/org/scalatra/scalatra/")
        else:
            # Общие fallback URL
            test_urls.append(f"{self.base_url}/repository/{repo_name}/.meta/")
            test_urls.append(f"{self.base_url}/repository/{repo_name}/v1/")
            test_urls.append(f"{self.base_url}/repository/{repo_name}/index.html")
        
        logger.debug(f"Performing additional checks for {repo_name} ({repo_format})")
        
        for url in test_urls:
            try:
                response = self.public_session.get(
                    url,
                    allow_redirects=False,
                    timeout=10
                )
                
                logger.debug(f"Additional check {url}: HTTP {response.status_code}")
                
                if response.status_code == 200:
                    result['status'] = 'vulnerable'
                    result['vulnerable'] = True
                    result['details'] = f'Public access via alternative endpoint: {url}'
                    result['alternative_url'] = url
                    logger.warning(f"VULNERABLE: {repo_name} allows public access via {url}")
                    return result
                
                elif response.status_code in [401, 403]:
                    result['status'] = 'secure'
                    result['details'] = f'Access requires authentication (checked {url})'
                    logger.info(f"SECURE: {repo_name} requires authentication (checked {url})")
                    return result
            
            except requests.exceptions.RequestException as e:
                logger.debug(f"Additional check failed for {url}: {e}")
                continue
        
        result['status'] = 'requires_manual_check'
        result['details'] = 'HTTP 400 received, manual check recommended'
        logger.info(f"REQUIRES MANUAL CHECK: {repo_name} returned HTTP 400")
        return result
    
    def _check_root_path(self, repository: Dict, result: Dict) -> Dict:
        """Проверка доступа к корневому пути репозитория"""
        repo_name = repository['name']
        root_url = f"{self.base_url}/repository/{repo_name}"
        
        try:
            response = self.public_session.get(
                root_url,
                allow_redirects=False,
                timeout=10
            )
            
            if response.status_code == 200:
                result['status'] = 'vulnerable'
                result['vulnerable'] = True
                result['details'] = 'Public access to repository root'
                result['root_url'] = root_url
                logger.warning(f"VULNERABLE: {repo_name} allows public access to root")
            
            elif response.status_code in [401, 403]:
                result['status'] = 'secure'
                result['details'] = 'Access requires authentication (root check)'
                logger.info(f"SECURE: {repo_name} requires authentication (root check)")
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Root check failed for {repo_name}: {e}")
        
        return result
    
    def audit(self) -> Tuple[List[Dict], Dict[str, Any]]:
        """Основной метод аудита"""
        logger.info("="*60)
        logger.info("Starting Nexus repository audit")
        logger.info(f"Nexus URL: {self.base_url}")
        logger.info(f"Repository types: {self.repo_types}")
        logger.info(f"Repository formats: {self.repo_formats if self.repo_formats else 'ALL'}")
        logger.info(f"SSL verify: {self.ssl_verify}, CA cert: {self.ca_cert}")
        logger.info(f"Prometheus export: {self.prometheus_enabled}")
        if self.prometheus_enabled:
            logger.info(f"Prometheus file: {self.prometheus_file}")
        logger.info(f"Email notifications: {self.email_enabled}")
        if self.email_enabled and EMAIL_MODULE_AVAILABLE:
            logger.info(f"Email recipients: {self.config['email'].get('to_emails', [])}")
        logger.info("="*60)
        
        try:
            # Начинаем захват консольного вывода
            self._start_capture_console()
            
            # Получаем все репозитории
            all_repositories = self.get_all_repositories()
            
            # Фильтруем репозитории
            repositories_to_check = self.filter_repositories(all_repositories)
            
            # Выполняем проверку
            results = []
            for repo in repositories_to_check:
                logger.info(f"Checking repository: {repo['name']} ({repo.get('format', 'unknown')})")
                result = self.test_repository_access(repo)
                results.append(result)
            
            # Формируем сводку
            summary = {
                'total_repositories': len(all_repositories),
                'checked': len(repositories_to_check),
                'vulnerable': sum(1 for r in results if r['vulnerable']),
                'secure': sum(1 for r in results if r['status'] == 'secure'),
                'requires_manual_check': sum(1 for r in results if r['status'] in ['requires_manual_check', 'special_check']),
                'errors': sum(1 for r in results if r['status'] in ['ssl_error', 'request_error', 'unexpected', 'connection_error', 'timeout']),
                'timestamp': int(time.time())
            }
            
            logger.info("Audit completed")
            logger.info(f"Summary: {summary}")
            
            # Останавливаем захват консольного вывода
            self._stop_capture_console()
            
            return results, summary
            
        except Exception as e:
            # Останавливаем захват в случае ошибки
            if hasattr(self, '_capture_buffer') and self._capture_buffer:
                self._stop_capture_console()
            logger.error(f"Audit failed: {e}")
            raise
    
    def generate_report(self, results: List[Dict], summary: Dict, output_file: str):
        """Генерация отчета и метрик Prometheus"""
        report = {
            'audit_configuration': {
                'nexus_url': self.base_url,
                'repository_types': self.repo_types,
                'repository_formats': self.repo_formats if self.repo_formats else 'ALL',
                'excluded_repositories': self.excluded_repos,
                'ssl_configuration': {
                    'verify_ssl': self.ssl_verify,
                    'ca_certificate': self.ca_cert,
                    'verify_hostname': self.verify_hostname
                },
                'prometheus_configuration': {
                    'enabled': self.prometheus_enabled,
                    'file': self.prometheus_file
                },
                'email_configuration': {
                    'enabled': self.email_enabled,
                    'recipients': self.config['email'].get('to_emails', []) if self.email_enabled else []
                },
                'timestamp': summary['timestamp'],
                'datetime': datetime.fromtimestamp(summary['timestamp']).isoformat()
            },
            'summary': summary,
            'results': results,
            'vulnerable_repositories': [
                {
                    'name': r['repository'],
                    'type': r['type'],
                    'format': r['format'],
                    'url': r['url'],
                    'details': r['details']
                }
                for r in results if r['vulnerable']
            ]
        }
        
        # Сохраняем JSON отчет
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON report saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving JSON report: {e}")
            output_file = f"nexus_audit_report_{int(time.time())}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON report saved to {output_file}")
        
        # Генерируем и сохраняем метрики Prometheus если включено
        if self.prometheus_enabled:
            metrics_content = self.metrics_exporter.generate_metrics(
                summary, results, self.base_url, summary['timestamp']
            )
            
            # Валидируем метрики перед записью
            if self._validate_prometheus_metrics(metrics_content):
                success = self.metrics_exporter.write_metrics_file(metrics_content, self.prometheus_file)
                if success:
                    report['prometheus_metrics_generated'] = True
                    report['prometheus_metrics_file'] = self.prometheus_file
                else:
                    report['prometheus_metrics_generated'] = False
                    report['prometheus_metrics_error'] = 'Failed to write metrics file'
            else:
                report['prometheus_metrics_generated'] = False
                report['prometheus_metrics_error'] = 'Metrics validation failed'
        
        # Отправляем email отчет если включено
        if self.email_enabled and self.email_sender:
            email_success = self.email_sender.send_report(
                summary, results, self.base_url, self.console_output
            )
            report['email_sent'] = email_success
            report['email_recipients'] = self.config['email'].get('to_emails', [])
            if email_success:
                logger.info(f"Email report sent to {len(report['email_recipients'])} recipients")
            else:
                logger.warning("Failed to send email report")
        
        # Выводим краткий отчет в консоль (уже захваченный)
        print(self.console_output)
    
    def _validate_prometheus_metrics(self, metrics_content: str) -> bool:
        """Валидация метрик Prometheus"""
        try:
            if not metrics_content:
                logger.error("Prometheus metrics content is empty")
                return False
            
            # Проверяем что файл заканчивается пустой строкой
            if not metrics_content.endswith('\n'):
                logger.error("Prometheus metrics must end with newline")
                return False
            
            # Проверяем базовую структуру
            lines = metrics_content.strip().split('\n')
            if len(lines) < 5:
                logger.error(f"Prometheus metrics too short: {len(lines)} lines")
                return False
            
            # Проверяем наличие HELP и TYPE
            help_count = sum(1 for line in lines if line.startswith('# HELP'))
            type_count = sum(1 for line in lines if line.startswith('# TYPE'))
            
            if help_count == 0 or type_count == 0:
                logger.error(f"Prometheus metrics missing HELP/TYPE lines: HELP={help_count}, TYPE={type_count}")
                return False
            
            # Проверяем корректность метрик
            for line in lines:
                if line and not line.startswith('#'):
                    # Проверяем что строка метрики содержит значение
                    if '}' in line:
                        parts = line.split('}', 1)
                        if len(parts) != 2 or ' ' not in parts[1]:
                            logger.error(f"Invalid metric line format: {line[:100]}")
                            return False
                    elif ' ' in line:
                        parts = line.split(' ', 1)
                        if len(parts) != 2:
                            logger.error(f"Invalid metric line format: {line[:100]}")
                            return False
                    else:
                        logger.error(f"Invalid metric line: {line[:100]}")
                        return False
            
            logger.debug(f"Prometheus metrics validation passed: {len(lines)} lines, {help_count} HELP, {type_count} TYPE")
            return True
            
        except Exception as e:
            logger.error(f"Prometheus metrics validation error: {e}")
            return False


def parse_comma_separated_list(value: str) -> List[str]:
    """Парсинг списка значений, разделенных запятыми"""
    if not value:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]


def main():
    parser = argparse.ArgumentParser(
        description='Nexus Repository Unauthorized Access Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Базовый запуск с конфигурационным файлом
  python nexus_auditor.py -c config.yaml
  
  # Включить email уведомления
  python nexus_auditor.py -c config.yaml --email
  
  # Включить email с указанием получателей
  python nexus_auditor.py -c config.yaml --email --email-to admin@example.com,security@example.com
  
  # Отключить email (переопределить конфиг)
  python nexus_auditor.py -c config.yaml --no-email
  
  # Комбинированный пример с email и Prometheus
  python nexus_auditor.py -c config.yaml --repo-types hosted --prometheus --email
  
  # Тест email отправки
  python nexus_auditor.py -c config.yaml --test-email

Email Configuration:
  • Email отправляется через SMTP localhost:25 без аутентификации
  • Поддерживается отправка нескольким получателям
  • Формат: HTML и plain text
  • Subject содержит статус аудита (CRITICAL/WARNING/SUCCESS)
        """
    )
    
    parser.add_argument('-c', '--config', required=True, 
                       help='Path to configuration file (YAML format)')
    parser.add_argument('-o', '--output', default='nexus_audit_report.json', 
                       help='Output report file (default: nexus_audit_report.json)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--debug-ssl', action='store_true', 
                       help='Enable SSL debugging')
    
    # Параметры для переопределения типов и форматов репозиториев
    parser.add_argument('--repo-types', type=parse_comma_separated_list,
                       help='Comma-separated list of repository types to check (overrides config). '
                            'Examples: hosted,proxy,group or hosted')
    
    parser.add_argument('--repo-formats', type=parse_comma_separated_list,
                       help='Comma-separated list of repository formats to check (overrides config). '
                            'Use empty string "" to check ALL formats. '
                            'Examples: maven2,docker,npm or "" for all')
    
    # Параметры для Prometheus
    prometheus_group = parser.add_mutually_exclusive_group()
    prometheus_group.add_argument('--prometheus', action='store_true', dest='prometheus_enabled',
                                 help='Enable Prometheus metrics export (overrides config)')
    prometheus_group.add_argument('--no-prometheus', action='store_false', dest='prometheus_enabled',
                                 help='Disable Prometheus metrics export (overrides config)')
    parser.set_defaults(prometheus_enabled=None)
    
    parser.add_argument('--prometheus-file', 
                       help='Path to Prometheus metrics file (overrides config)')
    
    # Параметры для Email
    email_group = parser.add_mutually_exclusive_group()
    email_group.add_argument('--email', action='store_true', dest='email_enabled',
                           help='Enable email notifications (overrides config)')
    email_group.add_argument('--no-email', action='store_false', dest='email_enabled',
                           help='Disable email notifications (overrides config)')
    parser.set_defaults(email_enabled=None)
    
    parser.add_argument('--email-to', type=str,
                       help='Comma-separated list of email recipients (overrides config). '
                            'Example: admin@example.com,security@example.com')
    
    parser.add_argument('--test-email', action='store_true',
                       help='Send test email and exit')
    
    # Добавляем флаг для отладки метрик
    parser.add_argument('--debug-metrics', action='store_true',
                       help='Enable Prometheus metrics debugging')
    
    args = parser.parse_args()
    
    # Проверяем доступность email модуля
    if not EMAIL_MODULE_AVAILABLE and (args.email_enabled or args.email_to or args.test_email):
        print("ERROR: Email module (email_sender.py) not found. Cannot send emails.")
        print("Make sure email_sender.py is in the same directory as nexus_auditor.py")
        sys.exit(1)
    
    if args.verbose or args.debug_metrics:
        logger.setLevel(logging.DEBUG)
    
    if args.debug_ssl:
        # Включаем подробное логирование SSL
        import http.client
        http.client.HTTPConnection.debuglevel = 1
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
    
    try:
        # Запуск аудита с переопределенными параметрами
        auditor = NexusAuditor(
            args.config,
            repo_types_override=args.repo_types,
            repo_formats_override=args.repo_formats,
            enable_prometheus_override=args.prometheus_enabled,
            prometheus_file_override=args.prometheus_file,
            enable_email_override=args.email_enabled,
            email_recipients_override=args.email_to
        )
        
        # Проверка отправки тестового email
        if args.test_email:
            if auditor.email_sender:
                success = auditor.email_sender.send_test_email()
                sys.exit(0 if success else 1)
            else:
                print("ERROR: Email sender not initialized. Check email configuration.")
                sys.exit(1)
        
        # Выполняем аудит
        results, summary = auditor.audit()
        
        # Генерация отчета
        auditor.generate_report(results, summary, args.output)
        
        # Возвращаем код выхода в зависимости от результатов
        if summary['vulnerable'] > 0:
            print("\n❌ Audit FAILED: Found repositories with public access")
            sys.exit(1)  # Есть уязвимости
        elif summary['errors'] > summary['checked'] / 2:
            print("\n⚠️  Audit completed with many errors")
            sys.exit(3)  # Много ошибок
        else:
            print("\n✅ Audit PASSED: No public access found")
            sys.exit(0)  # Все безопасно
    
    except KeyboardInterrupt:
        print("\n\nAudit interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        print(f"\n❌ Audit FAILED: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
