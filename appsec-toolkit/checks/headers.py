import requests

COMMON_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy", # More modern replacement for Feature-Policy
    "X-XSS-Protection" # Though deprecated and its use is discouraged, some older apps might still send it.
]

RECOMMENDED_MISSING_ADVICE = {
    "Content-Security-Policy": "Consider implementing CSP to prevent XSS and other injection attacks. Start with a restrictive policy and gradually allow necessary resources.",
    "Strict-Transport-Security": "Implement HSTS to ensure browsers only connect to your site via HTTPS, protecting against man-in-the-middle attacks.",
    "X-Content-Type-Options": "Set to 'nosniff' to prevent browsers from MIME-sniffing the content-type, which can lead to XSS vulnerabilities.",
    "X-Frame-Options": "Set to 'DENY' or 'SAMEORIGIN' to protect against clickjacking attacks.",
    "Referrer-Policy": "Consider setting a Referrer-Policy (e.g., 'strict-origin-when-cross-origin' or 'no-referrer') to control how much referrer information is sent.",
    "Permissions-Policy": "Define a Permissions-Policy to control which browser features can be used by the page (e.g., camera, microphone, geolocation).",
    "X-XSS-Protection": "This header is largely deprecated as modern browsers have built-in XSS filtering. CSP is the recommended replacement. If set, it should be '1; mode=block'."
}

def check_security_headers(url):
    """
    Checks a given URL for common security headers.
    Returns a dictionary with found and missing headers, along with advice.
    """
    results = {
        "url": url,
        "found_headers": {},
        "missing_headers": {},
        "recommendations": []
    }
    
    try:
        # Add a common user-agent to mimic a browser
        headers = {'User-Agent': 'AppSec-Toolkit-Scanner/1.0'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Normalize header names to lower case for consistent checking
        response_headers_lower = {k.lower(): v for k, v in response.headers.items()}

        for header in COMMON_SECURITY_HEADERS:
            if header.lower() in response_headers_lower:
                results["found_headers"][header] = response_headers_lower[header.lower()]
            else:
                results["missing_headers"][header] = RECOMMENDED_MISSING_ADVICE.get(header, "No specific recommendation available.")
                results["recommendations"].append(f"Missing {header}: {RECOMMENDED_MISSING_ADVICE.get(header, '')}")

    except requests.exceptions.RequestException as e:
        results["error"] = f"Could not connect to {url}. Error: {e}"
        results["recommendations"].append(f"Error scanning {url}: Could not connect or request timed out.")
        return results # Return early if connection fails
        
    return results

if __name__ == '__main__':
    # Example usage:
    # test_url = "https://www.google.com" # Replace with a site you want to test, or a local test server
    # test_url = "http://example.com" # Good for testing missing HSTS
    test_url = "https://owasp.org" # Generally has good headers
    
    print(f"🧪 Testing security headers for: {test_url}\n")
    header_results = check_security_headers(test_url)
    
    if header_results.get("error"):
        print(f"🚨 Error: {header_results['error']}")
    else:
        print("✅ Found Headers:")
        if header_results["found_headers"]:
            for header, value in header_results["found_headers"].items():
                print(f"  {header}: {value}")
        else:
            print("  None of the common security headers were found.")
            
        print("\n⚠️ Missing Headers & Recommendations:")
        if header_results["missing_headers"]:
            for header, advice in header_results["missing_headers"].items():
                print(f"  Missing: {header}\n    Recommendation: {advice}")
        else:
            print("  🎉 All common security headers checked are present!")
