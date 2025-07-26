"""
Exception classes for DriftBuddy.
Provides structured error handling and logging.
"""

from typing import Optional, Dict, Any
import structlog

logger = structlog.get_logger()


class DriftBuddyError(Exception):
    """Base exception class for DriftBuddy."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
        
        # Log the error
        logger.error("DriftBuddy error occurred",
                    error_code=error_code,
                    message=message,
                    details=details)


class ConfigurationError(DriftBuddyError):
    """Raised when there's a configuration issue."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFIG_ERROR", details)


class KICSError(DriftBuddyError):
    """Raised when there's an issue with KICS scanning."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "KICS_ERROR", details)


class SteampipeError(DriftBuddyError):
    """Raised when there's an issue with Steampipe integration."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "STEAMPIPE_ERROR", details)


class AIExplanationError(DriftBuddyError):
    """Raised when there's an issue with AI explanations."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AI_EXPLANATION_ERROR", details)


class ValidationError(DriftBuddyError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        if field:
            details = details or {}
            details["field"] = field
        super().__init__(message, "VALIDATION_ERROR", details)


class SecurityError(DriftBuddyError):
    """Raised when security-related issues occur."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "SECURITY_ERROR", details)


class TimeoutError(DriftBuddyError):
    """Raised when operations timeout."""
    
    def __init__(self, message: str, operation: Optional[str] = None,
                 timeout_seconds: Optional[int] = None,
                 details: Optional[Dict[str, Any]] = None):
        if operation or timeout_seconds:
            details = details or {}
            if operation:
                details["operation"] = operation
            if timeout_seconds:
                details["timeout_seconds"] = timeout_seconds
        super().__init__(message, "TIMEOUT_ERROR", details)


class FileError(DriftBuddyError):
    """Raised when there are file-related issues."""
    
    def __init__(self, message: str, file_path: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        if file_path:
            details = details or {}
            details["file_path"] = file_path
        super().__init__(message, "FILE_ERROR", details)


class NetworkError(DriftBuddyError):
    """Raised when there are network-related issues."""
    
    def __init__(self, message: str, url: Optional[str] = None,
                 status_code: Optional[int] = None,
                 details: Optional[Dict[str, Any]] = None):
        if url or status_code:
            details = details or {}
            if url:
                details["url"] = url
            if status_code:
                details["status_code"] = status_code
        super().__init__(message, "NETWORK_ERROR", details)


class DependencyError(DriftBuddyError):
    """Raised when required dependencies are missing or misconfigured."""
    
    def __init__(self, message: str, dependency: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        if dependency:
            details = details or {}
            details["dependency"] = dependency
        super().__init__(message, "DEPENDENCY_ERROR", details)


class ReportGenerationError(DriftBuddyError):
    """Raised when report generation fails."""
    
    def __init__(self, message: str, report_type: Optional[str] = None,
                 details: Optional[Dict[str, Any]] = None):
        if report_type:
            details = details or {}
            details["report_type"] = report_type
        super().__init__(message, "REPORT_GENERATION_ERROR", details)


# Error code mapping for consistent error handling
ERROR_CODES = {
    "CONFIG_ERROR": "Configuration issue",
    "KICS_ERROR": "KICS scanning issue",
    "STEAMPIPE_ERROR": "Steampipe integration issue",
    "AI_EXPLANATION_ERROR": "AI explanation issue",
    "VALIDATION_ERROR": "Input validation issue",
    "SECURITY_ERROR": "Security-related issue",
    "TIMEOUT_ERROR": "Operation timeout",
    "FILE_ERROR": "File operation issue",
    "NETWORK_ERROR": "Network communication issue",
    "DEPENDENCY_ERROR": "Missing or misconfigured dependency",
    "REPORT_GENERATION_ERROR": "Report generation issue",
}


def handle_exception(func):
    """Decorator to handle exceptions and provide consistent error handling."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except DriftBuddyError:
            # Re-raise DriftBuddy exceptions as they're already logged
            raise
        except Exception as e:
            # Convert other exceptions to DriftBuddyError
            logger.exception("Unexpected error occurred", 
                           function=func.__name__,
                           error_type=type(e).__name__,
                           error_message=str(e))
            raise DriftBuddyError(
                f"Unexpected error in {func.__name__}: {str(e)}",
                "UNEXPECTED_ERROR",
                {"original_error": type(e).__name__}
            )
    return wrapper


def safe_execute(func, *args, **kwargs):
    """Safely execute a function and return result or None on error."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.exception("Function execution failed",
                       function=func.__name__,
                       error=str(e))
        return None 