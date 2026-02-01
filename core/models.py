"""Модели данных."""
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class RepositoryCheckResult:
    """Результат проверки репозитория."""
    name: str
    type: str  # hosted, proxy, group
    format: str  # maven2, docker, npm и т.д.
    anonymous_access: bool = False
    status_code: Optional[int] = None
    is_exception: bool = False
    is_vulnerable: bool = False
    check_timestamp: datetime = None
    error: Optional[str] = None
    url_tested: str = ""
    check_method: str = ""
    details: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        if self.check_timestamp is None:
            self.check_timestamp = datetime.now()
    
    def to_dict(self) -> dict:
        """Преобразует объект в словарь."""
        data = asdict(self)
        data['check_timestamp'] = self.check_timestamp.isoformat()
        return data


@dataclass
class AuditResult:
    """Результаты аудита."""
    timestamp: datetime  # Изменено: теперь это datetime, а не float
    nexus_url: str
    repositories: List[RepositoryCheckResult]
    scan_duration: float
    summary: Dict[str, Any]
    config: Dict[str, Any]
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Преобразует объект в словарь."""
        result = {
            'timestamp': self.timestamp.isoformat(),  # Теперь это работает
            'nexus_url': self.nexus_url,
            'scan_duration': self.scan_duration,
            'config': self.config,
            'summary': self.summary,
            'repositories': [repo.to_dict() for repo in self.repositories],
            'grouped_summary': self._create_grouped_summary()
        }
        
        if self.error:
            result['error'] = self.error
        
        return result
    
    def _create_grouped_summary(self) -> Dict:
        """Создает сгруппированную сводку."""
        grouped = {
            'by_format': {},
            'by_type': {},
            'by_format_and_type': {},
            'vulnerable_repositories': [],
            'formats': sorted(set(r.format for r in self.repositories)),
            'types': sorted(set(r.type for r in self.repositories))
        }
        
        # Уязвимые репозитории
        grouped['vulnerable_repositories'] = [
            {
                'name': r.name,
                'type': r.type,
                'format': r.format,
                'status_code': r.status_code,
                'check_method': r.check_method
            }
            for r in self.repositories if r.is_vulnerable
        ]
        
        # Подсчет по форматам
        for repo in self.repositories:
            fmt = repo.format
            if fmt not in grouped['by_format']:
                grouped['by_format'][fmt] = {
                    'total': 0,
                    'anonymous_access': 0,
                    'vulnerable': 0,
                    'exceptions': 0
                }
            
            grouped['by_format'][fmt]['total'] += 1
            if repo.anonymous_access:
                grouped['by_format'][fmt]['anonymous_access'] += 1
            if repo.is_vulnerable:
                grouped['by_format'][fmt]['vulnerable'] += 1
            if repo.is_exception:
                grouped['by_format'][fmt]['exceptions'] += 1
        
        # Подсчет по типам
        for repo in self.repositories:
            repo_type = repo.type
            if repo_type not in grouped['by_type']:
                grouped['by_type'][repo_type] = {
                    'total': 0,
                    'anonymous_access': 0,
                    'vulnerable': 0,
                    'exceptions': 0
                }
            
            grouped['by_type'][repo_type]['total'] += 1
            if repo.anonymous_access:
                grouped['by_type'][repo_type]['anonymous_access'] += 1
            if repo.is_vulnerable:
                grouped['by_type'][repo_type]['vulnerable'] += 1
            if repo.is_exception:
                grouped['by_type'][repo_type]['exceptions'] += 1
        
        # Комбинированная группировка
        for repo in self.repositories:
            fmt = repo.format
            repo_type = repo.type
            
            if fmt not in grouped['by_format_and_type']:
                grouped['by_format_and_type'][fmt] = {}
            
            if repo_type not in grouped['by_format_and_type'][fmt]:
                grouped['by_format_and_type'][fmt][repo_type] = {
                    'total': 0,
                    'anonymous_access': 0,
                    'vulnerable': 0,
                    'exceptions': 0
                }
            
            grouped['by_format_and_type'][fmt][repo_type]['total'] += 1
            if repo.anonymous_access:
                grouped['by_format_and_type'][fmt][repo_type]['anonymous_access'] += 1
            if repo.is_vulnerable:
                grouped['by_format_and_type'][fmt][repo_type]['vulnerable'] += 1
            if repo.is_exception:
                grouped['by_format_and_type'][fmt][repo_type]['exceptions'] += 1
        
        return grouped
