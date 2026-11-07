from urllib.parse import urlsplit
import tldextract

def analyze_url(url):
    """
    Analyze a URL and extract its important components.

    Args:
        url (str): URL entered by the user.

    Returns:
        dict: Extracted URL information.

    Raises:
        ValueError: If the URL is invalid or incomplete.
    """

    # Remove unnecessary spaces
    url = url.strip()

    # Check whether the URL is empty
    if not url:
        raise ValueError("Please enter a URL.")

    # Parse the URL
    try:
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname

    except ValueError:
        raise ValueError("Invalid URL format.")

    # Check whether a valid hostname exists
    if not hostname:
        raise ValueError("URL does not contain a hostname.")

    # Accept only HTTP and HTTPS URLs
    if parsed_url.scheme.lower() not in ("http", "https"):
        raise ValueError("URL must use HTTP or HTTPS.")

    # Extract domain information
    extracted = tldextract.extract(hostname)

    # Store the extracted information
    analysis = {
        "original_url": url,
        "scheme": parsed_url.scheme,
        "hostname": hostname,
        "subdomain": extracted.subdomain,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "registered_domain": extracted.top_domain_under_public_suffix,
        "path": parsed_url.path,
        "query": parsed_url.query,
        "fragment": parsed_url.fragment
    }

    # Return the result
    return analysis
