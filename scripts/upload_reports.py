import requests
import sys
import os

DD_URL   = os.environ['DD_URL']
DD_TOKEN = os.environ['DD_TOKEN']
ENGAGEMENT_ID = os.environ['ENGAGEMENT_ID']

SCAN_TYPE_MAP = {
    'eslint-report.json': 'ESLint Scan',
    'gitleaks.json':      'Gitleaks Scan',
    'njsscan.sarif':      'SARIF',
    'npm-audit.json':     'NPM Audit Scan',
    'retire.json':        'Retire.js Scan',
    'semgrep.json':       'Semgrep JSON Report',
    'sbom.json':          'Anchore Grype',
}

def get_or_create_engagement(product_name, engagement_name):
    headers = {'Authorization': f'Token {DD_TOKEN}'}

    # Resolve product ID
    resp = requests.get(
        f'{DD_URL}/api/v2/products/',
        headers=headers,
        params={'name': product_name}
    )
    resp.raise_for_status()
    results = resp.json().get('results', [])
    if not results:
        raise SystemExit(f'[ERROR] Product "{product_name}" not found in DefectDojo')

    # Pick exact case match if multiple results returned
    product = next((p for p in results if p['name'] == product_name), results[0])
    product_id = product['id']
    print(f'[INFO] Product: {product["name"]} (ID: {product_id})')

    # Create engagement
    from datetime import date
    today = date.today().isoformat()
    resp = requests.post(
        f'{DD_URL}/api/v2/engagements/',
        headers={**headers, 'Content-Type': 'application/json'},
        json={
            'name':            engagement_name,
            'product':         product_id,
            'target_start':    today,
            'target_end':      today,
            'engagement_type': 'CI/CD',
            'status':          'In Progress',
        }
    )
    resp.raise_for_status()
    engagement_id = resp.json()['id']
    print(f'[INFO] Engagement created: {engagement_name} (ID: {engagement_id})')
    return engagement_id


def upload_report(file_path, engagement_id):
    file_name = os.path.basename(file_path)
    scan_type = SCAN_TYPE_MAP.get(file_name)

    if not scan_type:
        print(f'[WARN] No scan type mapping for {file_name} — skipping')
        return

    if not os.path.exists(file_path):
        print(f'[WARN] File not found: {file_path} — skipping')
        return

    print(f'[INFO] Uploading {file_name} as "{scan_type}"...')
    headers = {'Authorization': f'Token {DD_TOKEN}'}
    with open(file_path, 'rb') as f:
        resp = requests.post(
            f'{DD_URL}/api/v2/import-scan/',
            headers=headers,
            data={
                'engagement':       engagement_id,
                'scan_type':        scan_type,
                'active':           True,
                'verified':         False,
                'close_old_findings': True,
                'push_to_jira':     False,
                'minimum_severity': 'Low',
            },
            files={'file': f}
        )

    if resp.status_code == 201:
        print(f'[INFO] {file_name} uploaded successfully')
    else:
        print(f'[WARN] {file_name} upload failed (HTTP {resp.status_code}): {resp.text}')


def close_engagement(engagement_id):
    headers = {
        'Authorization':  f'Token {DD_TOKEN}',
        'Content-Type':   'application/json',
    }
    resp = requests.patch(
        f'{DD_URL}/api/v2/engagements/{engagement_id}/',
        headers=headers,
        json={'status': 'Completed'}
    )
    if resp.status_code == 200:
        print(f'[INFO] Engagement {engagement_id} closed successfully')
    else:
        print(f'[WARN] Failed to close engagement (HTTP {resp.status_code}): {resp.text}')


if __name__ == '__main__':
    if len(sys.argv) < 4:
        raise SystemExit('Usage: upload_reports.py <reports_dir> <product_name> <engagement_name>')

    reports_dir     = sys.argv[1]
    product_name    = sys.argv[2]
    engagement_name = sys.argv[3]

    engagement_id = get_or_create_engagement(product_name, engagement_name)

    for file_name in SCAN_TYPE_MAP.keys():
        upload_report(os.path.join(reports_dir, file_name), engagement_id)

    close_engagement(engagement_id)
