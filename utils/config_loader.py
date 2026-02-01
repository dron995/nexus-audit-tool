"""Загрузчик конфигурации."""
import os
import yaml
from typing import Dict, Any
import argparse


class ConfigLoader:
    """Класс для загрузки и управления конфигурацией."""
    
    @staticmethod
    def load_config(config_file: str) -> Dict[str, Any]:
        """Загружает конфигурацию из YAML файла."""
        default_config = {
            'nexus_url': None,
            'username': None,
            'password': None,
            'exceptions_file': None,
            'repo_types': ['hosted', 'proxy', 'group'],
            'max_workers': 10,
            'timeout': 30,
            'verify_ssl': True,
            'ca_bundle': None,
            'output_dir': 'reports',
            'save_reports': False,
            'prometheus': {
                'enabled': False,
                'output_dir': 'reports'
            },
            'email': {
                'enabled': False,
                'recipients': [],
                'sender': 'nexus-audit@localhost',
                'smtp_server': 'localhost',
                'smtp_port': 25,
                'send_json_attachment': True
            }
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f) or {}
            else:
                user_config = {}
            
            # Рекурсивное объединение конфигураций
            config = ConfigLoader._deep_merge(default_config, user_config)
            
            # Установка переменных окружения для паролей
            if config.get('username') and config['username'].startswith('${'):
                env_var = config['username'][2:-1]
                config['username'] = os.environ.get(env_var, '')
            
            if config.get('password') and config['password'].startswith('${'):
                env_var = config['password'][2:-1]
                config['password'] = os.environ.get(env_var, '')
            
            return config
            
        except Exception as e:
            raise Exception(f"Ошибка загрузки конфигурации {config_file}: {e}")
    
    @staticmethod
    def _deep_merge(default: Dict, custom: Dict) -> Dict:
        """Рекурсивное объединение словарей."""
        result = default.copy()
        
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigLoader._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    @staticmethod
    def override_config(config: Dict, args: argparse.Namespace) -> Dict:
        """Переопределяет конфигурацию аргументами командной строки."""
        if args.nexus_url:
            config['nexus_url'] = args.nexus_url
        if args.username:
            config['username'] = args.username
        if args.password:
            config['password'] = args.password
        if args.exceptions_file:
            config['exceptions_file'] = args.exceptions_file
        if args.repo_types:
            config['repo_types'] = args.repo_types
        if args.max_workers:
            config['max_workers'] = args.max_workers
        if args.ca_bundle:
            config['ca_bundle'] = args.ca_bundle
        if args.output_dir:
            config['output_dir'] = args.output_dir
        
        # SSL настройки
        if args.no_verify_ssl:
            config['verify_ssl'] = False
        
        # Prometheus настройки
        if args.prometheus:
            config['prometheus']['enabled'] = True
        if args.prometheus_output_dir:
            config['prometheus']['output_dir'] = args.prometheus_output_dir
        
        # Email настройки
        if args.email:
            config['email']['enabled'] = True
            config['email']['recipients'] = args.email
        if args.email_sender:
            config['email']['sender'] = args.email_sender
        if args.smtp_server:
            config['email']['smtp_server'] = args.smtp_server
        if args.smtp_port:
            config['email']['smtp_port'] = args.smtp_port
        if args.send_email:
            config['email']['enabled'] = True
        
        # Сохранение отчетов
        if args.save_reports:
            config['save_reports'] = True
        
        return config
