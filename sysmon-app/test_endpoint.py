import requests

try:
    r = requests.get('http://localhost:5000/api/report/pdf', timeout=120)
    print(f'Status: {r.status_code}')
    ct = r.headers.get('Content-Type', '')
    print(f'Content-Type: {ct}')
    if r.status_code != 200:
        print(f'Body: {r.text[:3000]}')
    else:
        print(f'PDF received OK, {len(r.content)} bytes')
except Exception as e:
    print(f'Request failed: {e}')
