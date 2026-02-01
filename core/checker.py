"""Проверка доступа к репозиториям."""
import requests
import random
import string
from typing import List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class RepositoryAccessChecker:
    """Класс для проверки доступа к репозиториям."""
    
    TEST_PATHS_BY_FORMAT = {
        'maven2': ['.meta', 'archetype-catalog.xml', 'maven-metadata.xml'],
        'docker': ['v2/', 'v2/_catalog'],
        'npm': ['-', '-/all'],
        'nuget': ['index.json', 'query'],
        'pypi': ['simple/', 'pypi'],
        'raw': ['test.txt', 'README.md'],
        'yum': ['repodata/repomd.xml'],
        'helm': ['index.yaml'],
        'rubygems': ['specs.4.8.gz'],
        'conda': ['channeldata.json'],
        'default': ['.meta', 'index.html']
    }
    
    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Генерация случайной строки для тестовых артефактов."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    @staticmethod
    def check_access_with_multiple_paths(
        nexus_url: str, 
        repo_name: str, 
        repo_format: str,
        verify: bool = True,
        session: requests.Session = None  # Добавляем параметр сессии
    ) -> Tuple[bool, Optional[int], str, str]:
        """
        Проверяет доступ через несколько тестовых путей.
        
        Args:
            nexus_url: URL Nexus
            repo_name: Имя репозитория
            repo_format: Формат репозитория
            verify: Проверять SSL
            session: Используемая сессия (если None, создается новая)
            
        Returns:
            Кортеж: (доступ, статус_код, использованный_url, метод)
        """
        base_url = f"{nexus_url.rstrip('/')}/repository/{repo_name}"
        
        # Используем переданную сессию или создаем новую
        if session is None:
            session = requests.Session()
        
        # Получаем тестовые пути для формата
        test_paths = RepositoryAccessChecker.TEST_PATHS_BY_FORMAT.get(
            repo_format, 
            RepositoryAccessChecker.TEST_PATHS_BY_FORMAT['default']
        )
        
        # Добавляем проверку корня (может вернуть 400)
        test_paths = [''] + test_paths
        
        for path in test_paths:
            url = f"{base_url}/{path}".rstrip('/')
            
            # Пробуем HEAD запрос
            try:
                response = session.head(url, timeout=10, verify=verify, allow_redirects=True)
                status_code = response.status_code
                
                if status_code in (200, 201, 202, 203, 204, 206, 404):
                    return True, status_code, url, f"HEAD {path}"
                elif status_code in (401, 403):
                    return False, status_code, url, f"HEAD {path}"
                elif status_code == 400:
                    continue
                    
            except requests.exceptions.RequestException as e:
                logger.debug(f"HEAD запрос не удался для {url}: {e}")
                continue
            
            # Пробуем GET запрос
            try:
                response = session.get(url, timeout=10, verify=verify, stream=True)
                response.close()
                status_code = response.status_code
                
                if status_code in (200, 201, 202, 203, 204, 206, 404):
                    return True, status_code, url, f"GET {path}"
                elif status_code in (401, 403):
                    return False, status_code, url, f"GET {path}"
                    
            except requests.exceptions.RequestException as e:
                logger.debug(f"GET запрос не удался для {url}: {e}")
                continue
        
        return False, None, base_url, "no successful checks"
