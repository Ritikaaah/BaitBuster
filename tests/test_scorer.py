import pytest
from api.scorer import calculate_risk_score

def test_empty_findings():
    result = calculate_risk_score([])

    assert result["score"] == 5
    assert result["category"] == "Low"

def test_low_severity():
    findings = [
        {"rule": "Test Rule", "severity": "low"}
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 10
    assert result["category"] == "Low"

def test_medium_severity():
    findings = [
        {"rule": "Test Rule", "severity": "medium"}
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 20
    assert result["category"] == "Low"

def test_high_severity():
    findings = [
        {"rule": "Test Rule", "severity": "high"}
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 30
    assert result["category"] == "Medium"

def test_multiple_findings():
    findings = [
        {"rule": "Rule 1", "severity": "low"},
        {"rule": "Rule 2", "severity": "medium"},
        {"rule": "Rule 3", "severity": "high"}
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 50
    assert result["category"] == "Medium"

def test_score_cannot_exceed_100():
    findings = [
        {"rule": "Rule", "severity": "high"}
        for _ in range(10)
    ]

    result = calculate_risk_score(findings)

    assert result["score"] == 100

def test_invalid_severity():
    findings = [
        {"rule": "Rule", "severity": "critical"}
    ]

    with pytest.raises(ValueError):
        calculate_risk_score(findings)

def test_invalid_finding():
    findings = [
        "This is not a dictionary"
    ]

    with pytest.raises(ValueError):
        calculate_risk_score(findings)