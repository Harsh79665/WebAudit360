"""WebAudit 360 — Structured Logging with Secret Redaction
Author: Harsh Patel
"""

import logging
import re
import sys
from typing import Any, Dict

# Regex patterns for sensitive keys and tokens
SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|api[_-]?key|bearer|token|auth|credential)["\']?\s*[:=]\s*["\']?([^"\'\s,;]+)'),
    re.compile(r'(?i)(authorization:\s*bearer\s+)([A-Za-z0-9_\-\.]+)'),
    re.compile(r'(?i)(cookie:\s*)([^\r\n]+)'),
]

REDACTED_TEXT = "[REDACTED]"


class SecretRedactingFormatter(logging.Formatter):
    """Logging formatter that automatically scrubs credentials, auth tokens, and secrets."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        redacted = original
        for pattern in SENSITIVE_PATTERNS:
            redacted = pattern.sub(r'\1: ' + REDACTED_TEXT, redacted)
        return redacted


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Configures application logger with secret redaction."""
    logger = logging.getLogger("webaudit360")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = SecretRedactingFormatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()

