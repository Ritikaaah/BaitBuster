from api.analyzer import analyze_url
from api.detector import detect_suspicious_features
from api.scorer import calculate_risk_score

#Helper function to run the complete analysis pipeline
def analyze_and_score(url):

    # Step 1: Analyze the URL
    analysis = analyze_url(url)

    # Step 2: Detect suspicious characteristics
    findings = detect_suspicious_features(analysis)

    # Step 3: Calculate the risk score
    result = calculate_risk_score(findings)

    return analysis, findings, result

#Normal Google URL
def test_google_url_pipeline():

    analysis, findings, result = analyze_and_score(
        "https://google.com"
    )

    assert analysis["registered_domain"] == "google.com"
    assert findings == []
    assert result["score"] == 5
    assert result["category"] == "Low"


#PayPal lookalike URL
def test_paypal_lookalike_pipeline():

    analysis, findings, result = analyze_and_score(
        "https://paypal.com.verify-account.xyz/login"
    )

    assert analysis["registered_domain"] == "verify-account.xyz"

    assert any(
        finding["rule"] == "Suspicious Keywords"
        for finding in findings
    )

    assert result["score"] == 25
    assert result["category"] == "Low"


#URL using an IP address
def test_ip_address_pipeline():

    analysis, findings, result = analyze_and_score(
        "https://192.168.1.1/login"
    )

    assert any(
        finding["rule"] == "IP Address"
        for finding in findings
    )

    assert any(
        finding["rule"] == "Suspicious Keywords"
        for finding in findings
    )

    assert result["score"] == 25
    assert result["category"] == "Low"