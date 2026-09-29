"""Service / product detection from banners and well-known port defaults."""

from __future__ import annotations

import re
from typing import Any

from tools.base import Tool

# Well-known port -> (service, product) defaults.
_PORT_DEFAULTS: dict[int, tuple[str, str]] = {
    80: ("http", "HTTP server"),
    443: ("https", "HTTP server"),
    8080: ("http", "HTTP server"),
    8000: ("http", "HTTP server"),
    22: ("ssh", "OpenSSH"),
    21: ("ftp", "FTP"),
    25: ("smtp", "SMTP"),
    3306: ("mysql", "MySQL"),
    5432: ("postgresql", "PostgreSQL"),
    6379: ("redis", "Redis"),
    9200: ("http", "Elasticsearch"),
}

# banner substring -> (service, product)
_BANNER_PATTERNS: list[tuple[str, str, str]] = [
    ("apache tomcat", "http", "Apache Tomcat"),
    ("tomcat", "http", "Apache Tomcat"),
    ("openssh", "ssh", "OpenSSH"),
    ("ssh-2.0", "ssh", "OpenSSH"),
    ("nginx", "http", "nginx"),
    ("apache", "http", "Apache HTTP Server"),
    ("iis", "http", "Microsoft IIS"),
    ("microsoft-httpapi", "http", "Microsoft IIS"),
    ("mysql", "mysql", "MySQL"),
    ("postgresql", "postgresql", "PostgreSQL"),
    ("redis", "redis", "Redis"),
    ("elasticsearch", "http", "Elasticsearch"),
]


class ServiceDetector(Tool):
    name = "service_detect"
    description = "Identify the service and product running on a port from its banner or port default."
    input_schema = {
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
            "port": {"type": "integer"},
            "banner": {"type": "string"},
        },
        "required": ["port"],
    }
    output_schema = {
        "type": "object",
        "properties": {
            "service": {"type": "string"},
            "product": {"type": "string"},
            "confidence": {"type": "number"},
        },
    }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        port = int(kwargs["port"])
        banner = str(kwargs.get("banner") or "").lower()
        service, product, confidence = None, None, 0.0

        for needle, s, p in _BANNER_PATTERNS:
            if needle in banner:
                service, product, confidence = s, p, 0.9
                break

        if service is None and port in _PORT_DEFAULTS:
            service, product = _PORT_DEFAULTS[port]
            confidence = 0.4

        service = service or "unknown"
        product = product or "unknown"
        return {"service": service, "product": product, "confidence": confidence}

    @staticmethod
    def version_from_banner(banner: str) -> str | None:
        """Best-effort version extraction from a banner string."""
        if not banner:
            return None
        m = re.search(r"\b(\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)\b", banner)
        return m.group(1) if m else None
