"""Основной аудитор Nexus."""
import time
import requests
from datetime import datetime
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import RepositoryCheckResult, AuditResult
from .checker import RepositoryAccessChecker
from utils.ssl_handler import SSLHandler


class NexusAuditor:
    """Основной класс аудитора Nexus."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.nexus_url = config['nexus_url'].rstrip('/')
        self.verify = SSLHandler.get_requests_verify(config)
        
        # Создаем две разных сессии:
        # 1. Для API запросов (с аутентификацией, если указана)
        self.api_session = self._create_api_session()
        
        # 2. Для проверки анонимного доступа (без аутентификации)
        self.anonymous_session = self._create_anonymous_session()
        
        self.exceptions = self._load_exceptions(config.get('exceptions_file'))
    
    def _create_api_session(self) -> requests.Session:
        """Создает HTTP сессию для API запросов."""
        session = requests.Session()
        
        # Аутентификация для API (опционально)
        username = self.config.get('username')
        password = self.config.get('password')
        if username and password:
            session.auth = (username, password)
        
        # Таймауты
        session.timeout = self.config.get('timeout', 30)
        
        # Заголовки для API
        session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'NexusAuditor/1.0'
        })
        
        return session
    
    def _create_anonymous_session(self) -> requests.Session:
        """Создает HTTP сессию для проверки анонимного доступа."""
        session = requests.Session()
        
        # НИКАКОЙ аутентификации!
        # Только базовые настройки
        
        session.timeout = self.config.get('timeout', 30)
        
        # Заголовки для анонимных запросов
        session.headers.update({
            'User-Agent': 'NexusAuditor-Anonymous/1.0'
        })
        
        return session
    
    def _load_exceptions(self, exceptions_file: str) -> List[str]:
        """Загружает список исключений."""
        if not exceptions_file:
            return []
        
        try:
            with open(exceptions_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            return []
    
    def get_all_repositories(self) -> List[Dict]:
        """Получает список всех репозиториев через API."""
        api_url = f"{self.nexus_url}/service/rest/v1/repositories"
        
        try:
            # Пробуем получить репозитории с аутентификацией
            response = self.api_session.get(api_url, timeout=30, verify=self.verify)
            
            # Если 401/403 - пробуем без аутентификации
            if response.status_code in (401, 403):
                logger.warning("API требует аутентификации. Пробуем получить репозитории другим способом...")
                return self._get_repositories_without_auth()
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Ошибка при получении репозиториев через API: {e}")
            logger.info("Пробуем получить репозитории без аутентификации...")
            return self._get_repositories_without_auth()
    
    def _get_repositories_without_auth(self) -> List[Dict]:
        """
        Альтернативный способ получения репозиториев без аутентификации.
        Менее точный, но работает, когда нет доступа к API.
        """
        repositories = []
        
        # Пробуем получить через публичные endpoints или известные пути
        known_formats = ['maven2', 'docker', 'npm', 'nuget', 'pypi', 'raw']
        known_types = ['hosted', 'proxy', 'group']
        
        # Если у нас есть информация о некоторых репозиториях, используем ее
        if self.config.get('known_repositories'):
            for repo_name in self.config.get('known_repositories', []):
                repositories.append({
                    'name': repo_name,
                    'type': 'unknown',
                    'format': 'unknown'
                })
        
        # Или возвращаем пустой список - будем проверять только известные пути
        if not repositories:
            logger.warning("Не удалось получить список репозиториев. Проверка будет ограничена.")
        
        return repositories
    
    def check_repository(self, repo_info: Dict) -> RepositoryCheckResult:
        """Проверяет один репозиторий."""
        repo_name = repo_info['name']
        repo_type = repo_info.get('type', 'unknown')
        repo_format = repo_info.get('format', 'unknown')
        
        is_exception = repo_name in self.exceptions
        
        result = RepositoryCheckResult(
            name=repo_name,
            type=repo_type,
            format=repo_format,
            is_exception=is_exception
        )
        
        try:
            # Используем анонимную сессию для проверки доступа
            access_granted, status_code, url_tested, check_method = \
                RepositoryAccessChecker.check_access_with_multiple_paths(
                    self.nexus_url,
                    repo_name,
                    repo_format,
                    self.verify,
                    self.anonymous_session  # Передаем анонимную сессию
                )
            
            result.anonymous_access = access_granted
            result.status_code = status_code
            result.url_tested = url_tested
            result.check_method = check_method
            
            result.is_vulnerable = (
                result.anonymous_access and 
                not result.is_exception and 
                result.error is None
            )
            
        except Exception as e:
            result.error = f"Неожиданная ошибка: {str(e)}"
        
        return result
    
    def run_audit(self) -> AuditResult:
        """Запускает полный аудит."""
        start_time = time.time()
        
        try:
            repositories_info = self.get_all_repositories()
        except Exception as e:
            # Возвращаем объект AuditResult с ошибкой
            return AuditResult(
                timestamp=datetime.now(),
                nexus_url=self.nexus_url,
                repositories=[],
                scan_duration=0,
                summary={},
                config={
                    'repo_types': self.config.get('repo_types'),
                    'exceptions_count': len(self.exceptions),
                    'verify_ssl': self.verify,
                    'auth_used': bool(self.config.get('username'))
                },
                error=str(e)
            )
        
        # Фильтрация по типам
        repo_types = self.config.get('repo_types', ['hosted', 'proxy', 'group'])
        if 'all' not in repo_types:
            repositories_info = [r for r in repositories_info if r.get('type') in repo_types]
        
        # Параллельная проверка
        results = []
        max_workers = self.config.get('max_workers', 10)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_repo = {
                executor.submit(self.check_repository, repo): repo['name']
                for repo in repositories_info
            }
            
            for future in as_completed(future_to_repo):
                repo_name = future_to_repo[future]
                try:
                    result = future.result(timeout=60)
                    results.append(result)
                except Exception as e:
                    results.append(RepositoryCheckResult(
                        name=repo_name,
                        type='unknown',
                        format='unknown',
                        error=f"Ошибка выполнения: {str(e)}"
                    ))
        
        scan_duration = time.time() - start_time
        
        # Создание сводки
        summary = self._create_summary(results)
        
        return AuditResult(
            timestamp=datetime.now(),
            nexus_url=self.nexus_url,
            repositories=results,
            scan_duration=scan_duration,
            summary=summary,
            config={
                'repo_types': self.config.get('repo_types'),
                'exceptions_count': len(self.exceptions),
                'verify_ssl': self.verify,
                'auth_used': bool(self.config.get('username')),
                'repositories_found': len(repositories_info)
            }
        )
    
    def _create_summary(self, results: List[RepositoryCheckResult]) -> Dict:
        """Создает сводку результатов."""
        summary = {
            'total': len(results),
            'anonymous_access': 0,
            'vulnerable': 0,
            'exceptions': 0,
            'errors': 0
        }
        
        for result in results:
            if result.error:
                summary['errors'] += 1
            if result.is_exception:
                summary['exceptions'] += 1
            if result.anonymous_access:
                summary['anonymous_access'] += 1
            if result.is_vulnerable:
                summary['vulnerable'] += 1
        
        return summary
