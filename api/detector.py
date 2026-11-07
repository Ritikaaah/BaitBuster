import ipaddress
from urllib.parse import urlsplit

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "signin",
    "password",
    "payment",
    "urgent",
    "confirm",
    "suspend",
    "banking",
    "wallet",
    "refund",
]

def detect_suspicious_features(analysis):
    """
    Examine extracted URL information and identify
    potentially suspicious characteristics.

    Args:
        analysis (dict): Output from analyze_url().

    Returns:
        list: List of suspicious findings.
    """

    findings = []

    url = analysis["original_url"]
    hostname = analysis["hostname"].lower()
    subdomain = analysis["subdomain"]
    parsed_url = urlsplit(url)

    #Check whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)

        findings.append({
            "rule": "IP Address",
            "severity": "medium",
            "message": "The URL uses an IP address instead of a domain name."
        })

    except ValueError:
        pass

    #Check for suspicious keywords.
    url_lower = url.lower()

    detected_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in url_lower
    ]

    if detected_keywords:
        findings.append({
            "rule": "Suspicious Keywords",
            "severity": "low",
            "message": (
                "The URL contains potentially suspicious words: "
                + ", ".join(detected_keywords)
            )
        })

    #Check for excessive subdomains.
    if subdomain:
        subdomain_count = len(subdomain.split("."))

        if subdomain_count >= 3:
            findings.append({
                "rule": "Excessive Subdomains",
                "severity": "medium",
                "message": (
                    f"The URL contains {subdomain_count} subdomain levels."
                )
            })

    #Check URL length.
    if len(url) > 100:
        findings.append({
            "rule": "Long URL",
            "severity": "low",
            "message": (
                f"The URL is unusually long ({len(url)} characters)."
            )
        })

    #Check for @ symbol in the network location.
    if "@" in parsed_url.netloc:
        findings.append({
            "rule": "At Symbol",
            "severity": "high",
            "message": (
                "The URL contains an @ symbol in its network location, "
                "which can obscure the actual hostname."
            )
        })

    #Check for punycode in the hostname.
    if "xn--" in hostname:
        findings.append({
            "rule": "Punycode",
            "severity": "medium",
            "message": (
                "The hostname contains punycode encoding. "
                "Check for possible lookalike characters."
            )
        })

    return findings