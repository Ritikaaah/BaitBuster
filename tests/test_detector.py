import pytest

from api.analyzer import analyze_url
from api.detector import detect_suspicious_features

def test_normal_url():

    result = analyze_url("https://google.com")
    findings = detect_suspicious_features(result)

    assert findings == []

def test_ip_address_detection():

    result = analyze_url("http://192.0.2.1/login")
    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "IP Address"
        for finding in findings
    )

def test_suspicious_keyword_detection():

    result = analyze_url(
        "https://example.com/urgent-payment-verification"
    )

    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "Suspicious Keywords"
        for finding in findings
    )

def test_excessive_subdomains():

    result = analyze_url(
        "https://one.two.three.example.com/login"
    )

    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "Excessive Subdomains"
        for finding in findings
    )

def test_long_url():

    url = "https://example.com/" + "a" * 110

    result = analyze_url(url)
    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "Long URL"
        for finding in findings
    )

def test_at_symbol_detection():

    result = analyze_url(
        "https://trusted.com@evil.example/login"
    )

    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "At Symbol"
        for finding in findings
    )

def test_punycode_detection():

    result = analyze_url("https://xn--pple-43d.com")

    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "Punycode"
        for finding in findings
    )

def test_two_subdomain_labels_not_flagged():

    result = analyze_url(
        "https://paypal.com.verify-account.xyz/login"
    )

    findings = detect_suspicious_features(result)

    assert not any(
        finding["rule"] == "Excessive Subdomains"
        for finding in findings
    )

def test_three_subdomain_labels_flagged():

    result = analyze_url(
        "https://one.two.three.example.com"
    )

    findings = detect_suspicious_features(result)

    assert any(
        finding["rule"] == "Excessive Subdomains"
        for finding in findings
    )

def test_paypal_lookalike_url_analysis():

    url = "https://paypal.com.verify-account.xyz/login"

    analysis = analyze_url(url)

    findings = detect_suspicious_features(analysis)

    assert analysis["registered_domain"] == "verify-account.xyz"

    detected_rules = [
        finding["rule"]
        for finding in findings
    ]

    assert "Suspicious Keywords" in detected_rules

    assert "Excessive Subdomains" not in detected_rules

def test_domain_like_subdomain_detection():

    analysis = {
        "original_url": "https://paypal.com.verify-account.xyz/login",
        "hostname": "paypal.com.verify-account.xyz",
        "subdomain": "paypal.com"
    }

    findings = detect_suspicious_features(analysis)

    assert any(
        finding["rule"] == "Domain-like Subdomain"
        for finding in findings
    )


def test_normal_subdomain_not_flagged():

    analysis = {
        "original_url": "https://mail.google.com",
        "hostname": "mail.google.com",
        "subdomain": "mail"
    }

    findings = detect_suspicious_features(analysis)

    assert not any(
        finding["rule"] == "Domain-like Subdomain"
        for finding in findings
    )