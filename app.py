from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List, Dict

app = Flask(__name__)

# Simple in-memory preview cache used by existing tests
preview_cache: Dict[str, str] = {}


def get_preview(url: str, use_js: bool = False, max_chars: int = 500) -> str:
    """Return a short text preview of the page and cache it."""
    if url in preview_cache:
        return preview_cache[url]

    # Keep this simple: fetch HTML and return text
    resp = requests.get(url, timeout=5)
    text = BeautifulSoup(resp.text, "html.parser").get_text()
    snippet = text[:max_chars]
    preview_cache[url] = snippet
    return snippet


def check_security_headers(response_or_headers) -> List[str]:
    """Check for presence of important security headers."""
    headers = None
    if hasattr(response_or_headers, "headers"):
        headers = response_or_headers.headers
    else:
        headers = response_or_headers

    lower_keys = {k.lower() for k in headers.keys()} if headers else set()
    required = {
        "content-security-policy": "Content-Security-Policy",
        "strict-transport-security": "Strict-Transport-Security",
        "x-frame-options": "X-Frame-Options",
    }

    findings = []
    for k, pretty in required.items():
        if k not in lower_keys:
            findings.append(f"Missing security header: {pretty}")

    return findings


def detect_trackers(soup: BeautifulSoup) -> List[str]:
    """Detect common tracker scripts (Google Analytics, Facebook Pixel, etc.)."""
    trackers = set()

    for script in soup.find_all("script"):
        src = (script.get("src") or "").lower()
        content = (script.string or "")
        content = content.lower() if isinstance(content, str) else ""
        combined = f"{src} {content}"

        if "googletagmanager" in combined or "google-analytics" in combined or "analytics.js" in combined or "gtag(" in combined or "ga(" in combined:
            trackers.add("Google Analytics")
        if "fbq(" in combined or "facebook" in combined:
            trackers.add("Facebook Pixel")
        if "adsbygoogle" in combined:
            trackers.add("Google AdSense")
        if "doubleclick" in combined or "g.doubleclick" in combined:
            trackers.add("DoubleClick")
        if "quantserve" in combined or "scorecardresearch" in combined:
            trackers.add("Tracking / Ad Network")

    return sorted(trackers)


def check_https(url: str, response=None) -> List[str]:
    """Verify whether the final served URL uses HTTPS."""
    final = None
    if response is not None and hasattr(response, "url"):
        final = response.url
    else:
        final = url

    scheme = urlparse(final).scheme if final else ""
    if scheme.lower() != "https":
        return ["Site is not served over HTTPS"]
    return []


def compute_security_score(missing_headers_count: int, trackers_count: int, has_https: bool) -> int:
    """Compute a simple security score based on findings."""
    score = 100
    score -= 20 * missing_headers_count
    score -= 10 * trackers_count
    if not has_https:
        score -= 30
    if score < 0:
        score = 0
    return score


def run_full_scan(url: str) -> Dict:
    """Perform HTTP fetch + security & privacy analysis, return structured results."""
    try:
        resp = requests.get(url, timeout=7)
        resp.raise_for_status()
    except Exception as e:
        return {"url": url, "error": str(e)}

    soup = BeautifulSoup(resp.text, "html.parser")

    header_findings = check_security_headers(resp)
    tracker_findings = detect_trackers(soup)
    https_findings = check_https(url, response=resp)

    findings = header_findings + tracker_findings + https_findings

    missing_headers_count = len(header_findings)
    trackers_count = len(tracker_findings)
    has_https = len(https_findings) == 0

    security_score = compute_security_score(missing_headers_count, trackers_count, has_https)

    preview = get_preview(url, use_js=False, max_chars=800)

    return {
        "url": resp.url,
        "security_score": security_score,
        "findings": findings,
        "preview": preview,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            return render_template("index.html", error="Please enter a URL to scan.")

        result = run_full_scan(url)

        if "error" in result:
            return render_template("result.html", url=url, error=result["error"]) 

        return render_template(
            "result.html",
            url=result["url"],
            security_score=result["security_score"],
            findings=result["findings"],
            preview=result["preview"],
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)

