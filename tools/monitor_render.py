import time
import requests

SERVICE_URL = 'https://privacy-checker-1.onrender.com'
POLL_INTERVAL = 60  # seconds
MAX_POLLS = 10


def check_site():
    try:
        r = requests.get(SERVICE_URL, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


if __name__ == '__main__':
    print(f'Polling {SERVICE_URL} up to {MAX_POLLS} times (every {POLL_INTERVAL}s)')
    for i in range(MAX_POLLS):
        status, body = check_site()
        print(f'[{i+1}/{MAX_POLLS}] status={status}')
        if status == 200:
            # Try to hit health endpoint
            try:
                h = requests.get(SERVICE_URL + '/health', timeout=5).json()
            except Exception as e:
                h = {"error": str(e)}
            print('Health:', h)
            # Optional: check a quick scan result
            try:
                s = requests.post(SERVICE_URL + '/', data={'url': 'https://example.com'}, timeout=20)
                print('Scan returned status', s.status_code)
                html = s.text or ''
                # Check for rendered screenshot
                if 'Rendered screenshot' in html or 'data:image/png;base64,' in html:
                    print('Rendered screenshot detected in scan output')
                    print('Service is fully ready — stopping monitor')
                    break
                else:
                    print('No rendered screenshot detected yet. Will continue polling.')
            except Exception as e:
                print('Scan request error:', e)

            # keep polling until max polls
        else:
            time.sleep(POLL_INTERVAL)
    else:
        print('Service did not report healthy status in time')
        else:
            time.sleep(POLL_INTERVAL)
    else:
        print('Service did not report healthy status in time')
