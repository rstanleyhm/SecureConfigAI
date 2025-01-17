import pytest
from app.api.scan import scan_file, scan_file_recursive
from app.utils.rules_loader import load_rules


def test_scan_file():
    content = {"DEBUG": "True", "PASSWORD": "12345", "ALLOWED_HOSTS": "*"}
    rules = load_rules()
    issues = scan_file(content, rules)
    assert len(issues) == 6  # Update to match the detected number of issues
    assert any(issue[1] == "Debug mode is enabled." for issue in issues)
    assert any(issue[1] == "Weak password detected." for issue in issues)
    assert any(
        issue[1] == "Broadly permissive allowed_hosts setting detected."
        for issue in issues
    )


def test_scan_file_recursive():
    data = {
        "app": {
            "debug": "true",
            "settings": {"password": "12345", "allowed_hosts": "*"},
        }
    }
    rules = load_rules()
    findings = scan_file_recursive(data, rules)
    assert len(findings) >= 3
    assert any(f[1] == "Debug mode is enabled." for f in findings)
    assert any(f[1] == "Weak password detected." for f in findings)


def test_scan_file_with_list_match_key():
    content = {"DEBUG": "True", "PASSWORD": "12345", "API_KEY": "abcdef123456"}
    rules = [
        {
            "id": "R040",
            "description": "Sensitive information exposed in configuration file.",
            "match_key": ["api_key", "password", "secret_key"],
            "severity": "critical",
        }
    ]
    issues = scan_file(content, rules)
    assert len(issues) == 2  # Matches both "API_KEY" and "PASSWORD"
    assert any(
        issue[1] == "Sensitive information exposed in configuration file."
        for issue in issues
    )
