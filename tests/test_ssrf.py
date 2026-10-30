"""WebAudit 360 — SSRF Defense Unit Tests
Author: Harsh Patel
"""

import pytest
from backend.app.core.ssrf import validate_target_url, SSRFValidationError, is_ip_blocked
import ipaddress


def test_public_domain_validation():
    """Valid public websites must pass SSRF validation cleanly."""
    url, host, ips = validate_target_url("https://example.com")
    assert url == "https://example.com"
    assert host == "example.com"
    assert len(ips) > 0


def test_loopback_rejection():
    """Loopback IPv4 and hostnames must be blocked."""
    with pytest.raises(SSRFValidationError):
        validate_target_url("http://127.0.0.1:8000")

    with pytest.raises(SSRFValidationError):
        validate_target_url("http://localhost:3000")

    with pytest.raises(SSRFValidationError):
        validate_target_url("http://127.0.1.5")


def test_rfc1918_private_network_rejection():
    """Private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) must be blocked."""
    with pytest.raises(SSRFValidationError):
        validate_target_url("http://10.0.0.1")

    with pytest.raises(SSRFValidationError):
        validate_target_url("https://172.20.0.5")

    with pytest.raises(SSRFValidationError):
        validate_target_url("http://192.168.1.254")


def test_cloud_metadata_rejection():
    """AWS/GCP/Azure link-local metadata IP (169.254.169.254) must be blocked."""
    with pytest.raises(SSRFValidationError):
        validate_target_url("http://169.254.169.254/latest/meta-data/")

    with pytest.raises(SSRFValidationError):
        validate_target_url("http://metadata.google.internal")


def test_invalid_scheme_rejection():
    """Protocols other than HTTP and HTTPS must be rejected."""
    with pytest.raises(SSRFValidationError):
        validate_target_url("file:///etc/passwd")

    with pytest.raises(SSRFValidationError):
        validate_target_url("gopher://127.0.0.1:6379")

    with pytest.raises(SSRFValidationError):
        validate_target_url("ftp://example.com")


def test_userinfo_rejection():
    """Userinfo inside URLs (user:pass@host) must be rejected to prevent credential leaks."""
    with pytest.raises(SSRFValidationError):
        validate_target_url("http://admin:secret@example.com")

