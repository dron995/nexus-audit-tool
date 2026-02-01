"""Обработчик SSL/TLS соединений."""
import os
import urllib3
import ssl
from typing import Dict


class SSLHandler:
    """Класс для настройки SSL контекста."""
    
    @staticmethod
    def setup_ssl_context(config: Dict) -> None:
        """Настройка SSL контекста."""
        verify_ssl = config.get('verify_ssl', True)
        ca_bundle = config.get('ca_bundle')
        
        if not verify_ssl:
            # Отключаем проверку SSL
            os.environ['REQUESTS_CA_BUNDLE'] = ''
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        elif ca_bundle and os.path.exists(ca_bundle):
            # Используем указанный CA bundle
            os.environ['REQUESTS_CA_BUNDLE'] = ca_bundle
        else:
            # Используем системные сертификаты
            default_ca_bundle = '/etc/ssl/certs/ca-certificates.crt'
            if os.path.exists(default_ca_bundle):
                os.environ['REQUESTS_CA_BUNDLE'] = default_ca_bundle
    
    @staticmethod
    def get_requests_verify(config: Dict):
        """Получить параметр verify для requests."""
        verify_ssl = config.get('verify_ssl', True)
        ca_bundle = config.get('ca_bundle')
        
        if not verify_ssl:
            return False
        elif ca_bundle and os.path.exists(ca_bundle):
            return ca_bundle
        else:
            return True
    
    @staticmethod
    def create_ssl_context(config: Dict) -> ssl.SSLContext:
        """Создает SSL контекст."""
        context = ssl.create_default_context()
        
        if not config.get('verify_ssl', True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif config.get('ca_bundle') and os.path.exists(config['ca_bundle']):
            context.load_verify_locations(cafile=config['ca_bundle'])
        
        return context
