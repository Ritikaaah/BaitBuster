import pytest

from api.analyzer import analyze_url

def test_simple_url():

    result = analyze_url("https://google.com")

    assert result["scheme"] == "https"
    assert result["hostname"] == "google.com"
    assert result["domain"] == "google"
    assert result["suffix"] == "com"
    assert result["registered_domain"] == "google.com"


def test_url_with_subdomain():

    result = analyze_url("https://login.google.co.uk/account")

    assert result["subdomain"] == "login"
    assert result["domain"] == "google"
    assert result["suffix"] == "co.uk"
    assert result["registered_domain"] == "google.co.uk"


def test_misleading_subdomain():

    result = analyze_url(
        "https://paypal.com.account-verification.example.com/signin"
    )

    assert result["subdomain"] == "paypal.com.account-verification"
    assert result["domain"] == "example"
    assert result["registered_domain"] == "example.com"


def test_empty_url():

    with pytest.raises(ValueError):
        analyze_url("")


def test_invalid_url():

    with pytest.raises(ValueError):
        analyze_url("hello")


def test_unsupported_scheme():

    with pytest.raises(ValueError):
        analyze_url("ftp://example.com")
