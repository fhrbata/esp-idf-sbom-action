import json
import os
import sys
import urllib.request
from subprocess import run

REPORT_JSON_FILE = 'report.json'
INPUT_REF = os.environ.get('INPUT_REF', os.environ['GITHUB_REF_NAME'])
GH_REPOSITORY = os.environ['GITHUB_REPOSITORY']
GH_SERVER_URL = os.environ['GITHUB_SERVER_URL']
GH_RUN_ID = os.environ['GITHUB_RUN_ID']
USER_NAME = f'{GH_REPOSITORY}@{INPUT_REF}'
JOB_URL = f'{GH_SERVER_URL}/{GH_REPOSITORY}/actions/runs/{GH_RUN_ID}'
SBOM_MATTERMOST_WEBHOOK = os.environ['SBOM_MATTERMOST_WEBHOOK']


def log(*args, **kwargs):
    print('*', *args, **kwargs)


def mattermost_msg(msg: str) -> None:
    if SBOM_MATTERMOST_WEBHOOK is None:
        return
    data = {
        'username': USER_NAME,
        'text': msg
    }
    req = urllib.request.Request(SBOM_MATTERMOST_WEBHOOK,
                                 headers={'Content-Type': 'application/json'},
                                 data=json.dumps(data).encode())
    urllib.request.urlopen(req)


log(f'INPUT_REF: {INPUT_REF}')
log(f'USER_NAME: {USER_NAME}')
log(f'JOB_URL: {JOB_URL}')

log('installing esp-idf-sbom ...')
run(['pip', 'install', 'esp-idf-sbom'], check=True)

log('running vulnerability check ...')
try:
    p = run(['python', '-m', 'esp_idf_sbom', 'manifest', 'check', '--name',
             '--format', 'json', '--output-file', REPORT_JSON_FILE,
             '/github/workspace'])
except Exception:
    mattermost_msg(f':warning: Vulnerabilities scan failed {JOB_URL}')
    raise

if p.returncode == 128:
    mattermost_msg(f':warning: Vulnerabilities scan failed {JOB_URL}')
    sys.exit(1)


log('loading vulnerability report json file ...')
with open(REPORT_JSON_FILE) as f:
    data = json.load(f)

log('json report data', json.dumps(data, indent=4))

vulnerable_yes: list = []
vulnerable_maybe: list = []

for record in data['records']:
    if record['vulnerable'] == 'YES':
        vulnerable_yes.append(record)
    elif record['vulnerable'] == 'MAYBE':
        vulnerable_maybe.append(record)

if not vulnerable_yes and not vulnerable_maybe:
    mattermost_msg(f':large_green_circle: No vulnerabilities found {JOB_URL}')
    sys.exit()

report_list: list = []
report_list.append('|Vulnerable|Package|Version|CVE|Severity|')
report_list.append('|----------|-------|-------|---|--------|')
for r in vulnerable_yes + vulnerable_maybe:
    report_list.append((f'|{r["vulnerable"]}'
                        f'|{r["pkg_name"]}'
                        f'|{r["pkg_version"]}'
                        f'|[{r["cve_id"]}]({r["cve_link"]})'
                        f'|{r["cvss_base_severity"]}|'))

report_str = '\n'.join(report_list)

if vulnerable_yes:
    mattermost_msg(f':red_circle: New vulnerabilities found {JOB_URL}\n\n{report_str}')
else:
    mattermost_msg((f':large_yellow_circle: Possible new vulnerabilities '
                    f'found(might include false positives) {JOB_URL}\n\n{report_str}'))
