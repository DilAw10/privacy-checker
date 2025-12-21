from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List, Dict, Optional
import base64

# Try to import Playwright; gracefully degrade if not available
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

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


def render_with_playwright(url: str, timeout: int = 10) -> Dict[str, Optional[str]]:
    """Render the page with Playwright and return text preview and a PNG screenshot (base64).
    Returns a dict with keys: 'text', 'screenshot' (base64), 'error' (str or None)
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {"text": None, "screenshot": None, "error": "Playwright not available"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])  # Render-friendly
            page = browser.new_page()
            page.goto(url, timeout=timeout * 1000, wait_until="networkidle")

            # Get page content text and a screenshot
            body_text = page.inner_text("body") if page.locator('body').count() else page.content()
            screenshot_bytes = page.screenshot(type="png")

            browser.close()

            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii") if screenshot_bytes else None
            return {"text": body_text, "screenshot": screenshot_b64, "error": None}

    except PlaywrightTimeoutError as e:
        return {"text": None, "screenshot": None, "error": f"Playwright timeout: {e}"}
    except Exception as e:
        return {"text": None, "screenshot": None, "error": f"Playwright error: {e}"}


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


def sanitize_html(html: str) -> str:
    """Sanitize HTML by removing script tags and event handler attributes.
    Uses BeautifulSoup to strip potentially dangerous parts while preserving structure.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Remove all script tags
    for script in soup.find_all("script"):
        script.decompose()

    # Remove attributes that start with on* (onclick, onload, etc.) and javascript: URLs
    for tag in soup.find_all(True):
        attrs = dict(tag.attrs)
        for attr, val in attrs.items():
            if attr.lower().startswith("on"):
                del tag.attrs[attr]
                continue
            if attr.lower() in ("href", "src") and isinstance(val, str) and val.strip().lower().startswith("javascript:"):
                del tag.attrs[attr]

    return str(soup)


def run_full_scan(url: str, use_js: bool = False) -> Dict:
    """Perform HTTP fetch + security & privacy analysis, return structured results."""
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        return {"url": url, "error": str(e)}

    # If JS rendering requested and Playwright available, try to use it
    render_info = None
    screenshot_b64 = None
    raw_html = resp.text
    if use_js:
        rendered = render_with_playwright(url)
        if rendered.get("error"):
            # Playwright failed -> fall back to standard response HTML
            render_info = rendered["error"]
            soup = BeautifulSoup(resp.text, "html.parser")
        else:
            render_info = "Rendered via Playwright"
            # Use rendered text for analysis
            text_for_analysis = rendered.get("text") or ""
            screenshot_b64 = rendered.get("screenshot")
            raw_html = text_for_analysis
            soup = BeautifulSoup(text_for_analysis, "html.parser")
    else:
        soup = BeautifulSoup(resp.text, "html.parser")

    header_findings = check_security_headers(resp)
    tracker_findings = detect_trackers(soup)
    https_findings = check_https(url, response=resp)

    findings = header_findings + tracker_findings + https_findings

    missing_headers_count = len(header_findings)
    trackers_count = len(tracker_findings)
    has_https = len(https_findings) == 0

    security_score = compute_security_score(missing_headers_count, trackers_count, has_https)

    # Prefer Playwright text preview if available
    if use_js and render_info == "Rendered via Playwright":
        preview = (soup.get_text()[:800]) if soup else ""
    else:
        preview = get_preview(url, use_js=False, max_chars=800)

    sanitized_html = sanitize_html(raw_html) if raw_html else ""

    result = {
        "url": resp.url,
        "security_score": security_score,
        "findings": findings,
        "preview": preview,
        "raw_html": raw_html,
        "sanitized_html": sanitized_html,
        "sanitized_html_b64": base64.b64encode(sanitized_html.encode("utf-8")).decode("ascii") if sanitized_html else None,
        "playwright": {
            "available": PLAYWRIGHT_AVAILABLE,
            "info": render_info,
        },
    }

    if screenshot_b64:
        result["screenshot"] = screenshot_b64

    return result


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        render_js = bool(request.form.get("render_js"))
        if not url:
            return render_template("index.html", error="Please enter a URL to scan.")

        result = run_full_scan(url, use_js=render_js)

        if "error" in result:
            return render_template("result.html", url=url, error=result["error"]) 

        return render_template(
            "result.html",
            url=result["url"],
            security_score=result["security_score"],
            findings=result["findings"],
            preview=result["preview"],
            sanitized_html=result.get("sanitized_html"),
            sanitized_html_b64=result.get("sanitized_html_b64"),
            playwright=result.get("playwright"),
            screenshot=result.get("screenshot"),
        )

    return render_template("index.html")


@app.route('/health')
def health():
    return jsonify({"ok": True, "playwright": PLAYWRIGHT_AVAILABLE})


if __name__ == "__main__":
    app.run(debug=True)

