"""
Configuration management for DriftBuddy.
Handles environment variables, settings, and configuration validation.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pydantic import BaseSettings, Field, validator
import structlog

logger = structlog.get_logger()


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Application settings
    app_name: str = "DriftBuddy"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False, env="DEBUG")
    
    # Logging configuration
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="json", env="LOG_FORMAT")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # OpenAI configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-3.5-turbo", env="OPENAI_MODEL")
    openai_max_tokens: int = Field(default=2000, env="OPENAI_MAX_TOKENS")
    
    # KICS configuration
    kics_timeout: int = Field(default=300, env="KICS_TIMEOUT")
    kics_output_dir: str = Field(default="test_data/output", env="KICS_OUTPUT_DIR")
    kics_queries_path: Optional[str] = Field(default=None, env="KICS_QUERIES_PATH")
    
    # Steampipe configuration
    steampipe_timeout: int = Field(default=300, env="STEAMPIPE_TIMEOUT")
    steampipe_plugins: list = Field(default=["aws", "azure", "gcp"], env="STEAMPIPE_PLUGINS")
    
    # Output configuration
    reports_dir: str = Field(default="outputs/reports", env="REPORTS_DIR")
    analysis_dir: str = Field(default="outputs/analysis", env="ANALYSIS_DIR")
    
    # Security settings
    enable_secrets_scanning: bool = Field(default=True, env="ENABLE_SECRETS_SCANNING")
    max_file_size_mb: int = Field(default=100, env="MAX_FILE_SIZE_MB")
    
    # Performance settings
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    scan_timeout_minutes: int = Field(default=30, env="SCAN_TIMEOUT_MINUTES")
    
    # Feature flags
    enable_ai_explanations: bool = Field(default=True, env="ENABLE_AI_EXPLANATIONS")
    enable_html_reports: bool = Field(default=True, env="ENABLE_HTML_REPORTS")
    enable_markdown_reports: bool = Field(default=True, env="ENABLE_MARKDOWN_REPORTS")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    @validator("log_level")
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()
    
    @validator("log_format")
    def validate_log_format(cls, v):
        valid_formats = ["json", "text", "console"]
        if v.lower() not in valid_formats:
            raise ValueError(f"Log format must be one of {valid_formats}")
        return v.lower()
    
    @validator("steampipe_plugins")
    def validate_steampipe_plugins(cls, v):
        valid_plugins = ["aws", "azure", "gcp", "kubernetes", "docker"]
        for plugin in v:
            if plugin not in valid_plugins:
                raise ValueError(f"Invalid Steampipe plugin: {plugin}")
        return v


@dataclass
class Config:
    """Configuration manager for DriftBuddy."""
    
    settings: Settings = field(default_factory=Settings)
    _initialized: bool = field(default=False, init=False)
    
    def __post_init__(self):
        """Initialize configuration after creation."""
        if not self._initialized:
            self._setup_logging()
            self._validate_paths()
            self._initialized = True
    
    def _setup_logging(self):
        """Configure structured logging."""
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
        ]
        
        if self.settings.log_format == "json":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
        
        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        # Set log level
        import logging
        logging.basicConfig(
            level=getattr(logging, self.settings.log_level),
            format="%(message)s" if self.settings.log_format == "json" else None
        )
        
        logger.info("Logging configured", 
                   level=self.settings.log_level, 
                   format=self.settings.log_format)
    
    def _validate_paths(self):
        """Validate and create necessary directories."""
        paths_to_create = [
            self.settings.reports_dir,
            self.settings.analysis_dir,
            self.settings.kics_output_dir,
        ]
        
        for path in paths_to_create:
            Path(path).mkdir(parents=True, exist_ok=True)
            logger.debug("Ensured directory exists", path=path)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return getattr(self.settings, key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        if hasattr(self.settings, key):
            setattr(self.settings, key, value)
            logger.info("Configuration updated", key=key, value=value)
        else:
            logger.warning("Attempted to set unknown configuration key", key=key)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.settings.dict()
    
    def validate(self) -> bool:
        """Validate configuration."""
        try:
            # Validate required settings
            if self.settings.enable_ai_explanations and not self.settings.openai_api_key:
                logger.warning("AI explanations enabled but OpenAI API key not provided")
            
            # Validate paths
            for path in [self.settings.reports_dir, self.settings.analysis_dir]:
                if not os.access(path, os.W_OK):
                    logger.error("Directory not writable", path=path)
                    return False
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error("Configuration validation failed", error=str(e))
            return False


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance."""
    return config


def reload_config() -> Config:
    """Reload configuration from environment."""
    global config
    config = Config()
    return config 