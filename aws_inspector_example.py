import boto3
from dsp3.models.manager import Manager


ai = boto3.client('inspector')
findings = ai.list_findings()

findings_dict = ai.describe_findings(findingArns=findings['findingArns'])
cves = []

for finding in findings_dict['findings']:
    for attr in finding['attributes']:
        if attr['key'] == 'CVE_ID':
            cves.append(attr['value'])


print("Amazon Inspector Findings")
print(cves)

dsm = Manager(username="username", password="password", tenant="ACME CORP")
print("Getting DPI rules from DSM")
rules = dsm.dpi_rules_all()

dsm_cves_all  = []
dsm_cves = []
for rule in rules:
    if 'cveNumbers'in rule and rule['cveNumbers'] != None:
        for cve in rule['cveNumbers'].split(","):
            dsm_cves_all.append(cve.strip())
            if cve.strip() in cves:
                dsm_cves.append(cve)

print()
print("DSM Coverage")
print(dsm_cves)
print(cves)
print("*******************************************")
print(dsm_cves_all)
print(set(cves) & set(dsm_cves))
dsm.end_session()