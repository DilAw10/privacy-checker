import os
import re
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import ssl
import socket
from datetime import datetime

load_dotenv()
app = Flask(__name__)

# --- Website Security & Privacy Testing Functions ---

def validate_url(url):
    """Validate and normalize URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        result = urlparse(url)
        if not result.netloc:
            return None, "Invalid URL format"
        return url, None
    except:
        return None, "Invalid URL format"

def check_ssl_certificate(domain):
    """Check SSL certificate validity and expiration."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days
                
                return {
                    'valid': True,
                    'issuer': cert.get('issuer', [{}])[0].get('commonName', 'Unknown'),
                    'expires': cert['notAfter'],
                    'days_left': days_left,
                    'status': 'Valid' if days_left > 30 else ('Expiring Soon' if days_left > 0 else 'Expired')
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'status': 'No SSL Certificate'
        }

def check_security_headers(url):
    """Check for important security headers."""
    headers_to_check = {
        'Strict-Transport-Security': 'HSTS',
        'X-Content-Type-Options': 'Content-Type Protection',
        'X-Frame-Options': 'Clickjacking Protection',
        'Content-Security-Policy': 'CSP',
        'X-XSS-Protection': 'XSS Protection',
        'Referrer-Policy': 'Referrer Policy'
    }
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        found_headers = {}
        missing_headers = []
        
        for header, description in headers_to_check.items():
            if header in response.headers:
                found_headers[description] = response.headers[header]
            else:
                missing_headers.append(description)
        
        return {
            'found': found_headers,
            'missing': missing_headers,
            'status_code': response.status_code
        }
    except Exception as e:
        return {'error': str(e)}

def check_privacy_policies(url):
    """Check for privacy policy and terms."""
    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()
        
        checks = {
            'Privacy Policy': '/privacy' in response.text or 'privacy policy' in content,
            'Terms of Service': '/terms' in response.text or 'terms of service' in content,
            'Cookie Policy': '/cookies' in response.text or 'cookie' in content,
            'Contact Page': '/contact' in response.text or 'contact' in content,
            'Data Protection': 'gdpr' in content or 'data protection' in content
        }
        
        return checks
    except Exception as e:
        return {'error': str(e)}

def check_trackers(url):
    """Detect common tracking scripts."""
    trackers = {
        'Google Analytics': ['google-analytics', 'gtag', '_ga'],
        'Facebook Pixel': ['facebook.com/tr', 'fbq'],
        'LinkedIn Insight': ['linkedin.com/insight'],
        'Hotjar': ['heatmap.it', 'hjcdn.com'],
        'Mixpanel': ['mixpanel.com'],
        'Segment': ['segment.com', 'analytics.js'],
        'Crazy Egg': ['crazyegg.com'],
        'New Relic': ['newrelic.com'],
        'Intercom': ['intercomcdn.com'],
        'Drift': ['drift.com']
    }
    
    try:
        response = requests.get(url, timeout=10)
        content = response.text
        found_trackers = []
        
        for tracker_name, identifiers in trackers.items():
            for identifier in identifiers:
                if identifier.lower() in content.lower():
                    found_trackers.append(tracker_name)
                    break
        
        return {
            'found': found_trackers,
            'total_trackers': len(found_trackers),
            'severity': 'High' if len(found_trackers) > 5 else ('Medium' if len(found_trackers) > 2 else 'Low')
        }
    except Exception as e:
        return {'error': str(e)}

def check_https(url):
    """Check if site uses HTTPS."""
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        is_https = response.url.startswith('https://')
        return {
            'uses_https': is_https,
            'final_url': response.url,
            'status': 'Secure (HTTPS)' if is_https else 'Not Secure (HTTP)'
        }
    except Exception as e:
        return {'error': str(e)}

def run_full_scan(url):
    """Run complete security and privacy scan."""
    normalized_url, error = validate_url(url)
    if error:
        return {'error': error}
    
    domain = urlparse(normalized_url).netloc
    
    return {
        'url': normalized_url,
        'domain': domain,
        'ssl': check_ssl_certificate(domain),
        'https': check_https(normalized_url),
        'security_headers': check_security_headers(normalized_url),
        'privacy_policies': check_privacy_policies(normalized_url),
        'trackers': check_trackers(normalized_url)
    }

# --- Flask Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            results = run_full_scan(url)
    
    return render_template('index.html', results=results)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for website scanning."""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    results = run_full_scan(url)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
