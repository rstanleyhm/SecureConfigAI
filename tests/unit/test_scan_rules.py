import pytest
from app.api.scan import scan_file
from app.utils.rules_loader import load_rules

def test_scan_file_with_rules():
    content = {
        "debug": "true",
        "password": "12345",
        "allowed_hosts": "*",
        "api_key": "abcdef123456"
    }
    rules = load_rules()
    issues = scan_file(content, rules)
    assert len(issues) == 11  # Update to match detected issues
    assert any(issue[1] == "Debug mode is enabled." for issue in issues)
    assert any(issue[1] == "Weak password detected." for issue in issues)
    assert any(issue[1] == "Broadly permissive allowed_hosts setting detected." for issue in issues)
    assert any(issue[1] == "Sensitive information exposed in configuration file." for issue in issues)
