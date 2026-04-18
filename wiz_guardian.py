"""
WizGuardian - Multi-Region AWS Security Scanner
Author: Guy Peleg | guypeleg2004@gmail.com
Submitted as bonus alongside Wiz Technical Security Analyst Home Assignment

Operationalizes the Q1 (IMDSv1) and Q2 (Insecure SG Ports) Rego detection logic
into a live multi-region Python scanner using boto3.
"""

import boto3
import logging

# ─── Logging (replaces bare except: pass) ────────────────────────────────────
logging.basicConfig(level=logging.WARNING, format='[%(levelname)s] %(message)s')
log = logging.getLogger('WizGuardian')

# ─── Configuration ────────────────────────────────────────────────────────────
session = boto3.Session()
ec2_client = session.client('ec2')

SAFE_TCP_PORTS = [22, 53, 135, 443, 445, 563, 993]
SEVERITY_RANK  = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Dynamically discover all regions; fall back to us-east-1 if IAM is restricted
try:
    ALL_REGIONS = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
except Exception as e:
    log.warning(f"Could not fetch all regions (IAM-limited account?): {e}")
    ALL_REGIONS = ["us-east-1"]


# ─── Scanner ──────────────────────────────────────────────────────────────────
class WizGuardian:
    def __init__(self, region):
        self.region = region
        self.ec2 = session.client('ec2', region_name=region)
        self.findings = []
        self.max_severity_rank = 0

    def add_finding(self, risk, finding_type, resource, detail, remediation):
        self.findings.append({
            "Risk":        risk,
            "Type":        finding_type,
            "Resource":    resource,
            "Detail":      detail,
            "Remediation": remediation,
        })
        if SEVERITY_RANK[risk] > self.max_severity_rank:
            self.max_severity_rank = SEVERITY_RANK[risk]

    def _audit_security_groups(self):
        """Check for inbound rules with insecure ports (mirrors Q2 Rego policy)."""
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
        except Exception as e:
            log.error(f"[{self.region}] Failed to describe security groups: {e}")
            return

        for sg in sgs:
            if sg['GroupName'] == 'default':
                continue  # Skip default SGs

            for perm in sg.get('IpPermissions', []):
                protocol  = perm.get('IpProtocol')
                from_port = perm.get('FromPort')

                insecure = (
                    protocol == '-1'  # All-traffic rule
                    or (
                        protocol != 'icmp'
                        and from_port is not None
                        and from_port < 1024
                        and from_port not in SAFE_TCP_PORTS
                    )
                )

                if insecure:
                    port_label = from_port if from_port is not None else 'ALL'
                    self.add_finding(
                        risk        = "MEDIUM",
                        finding_type= "INSECURE NETWORK RULE",
                        resource    = sg['GroupId'],
                        detail      = f"Port {port_label} ({sg['GroupName']})",
                        remediation = (
                            f"aws ec2 revoke-security-group-ingress "
                            f"--group-id {sg['GroupId']} "
                            f"--protocol {protocol} "
                            f"--port {port_label} "
                            f"--cidr 0.0.0.0/0 "
                            f"--region {self.region}"
                        ),
                    )

    def _audit_imds(self):
        """Check for EC2 instances with IMDSv1 enabled (mirrors Q1 Rego policy)."""
        try:
            instances_resp = self.ec2.describe_instances()
        except Exception as e:
            log.error(f"[{self.region}] Failed to describe instances: {e}")
            return

        for reservation in instances_resp['Reservations']:
            for inst in reservation['Instances']:
                http_tokens = inst.get('MetadataOptions', {}).get('HttpTokens', 'optional')
                if http_tokens != 'required':
                    self.add_finding(
                        risk        = "HIGH",
                        finding_type= "IMDSv1 ENABLED",
                        resource    = inst['InstanceId'],
                        detail      = "SSRF Risk - HttpTokens not required",
                        remediation = (
                            f"aws ec2 modify-instance-metadata-options "
                            f"--instance-id {inst['InstanceId']} "
                            f"--http-tokens required "
                            f"--region {self.region}"
                        ),
                    )

    def scan(self):
        self._audit_security_groups()
        self._audit_imds()


# ─── Report ───────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 80)
    print("  WizGuardian - Multi-Region Cloud Security Scanner")
    print("=" * 80)

    reports = []
    for region in ALL_REGIONS:
        print(f"  [*] Scanning {region}...", end='\r')
        guardian = WizGuardian(region)
        guardian.scan()
        if guardian.findings:
            reports.append(guardian)

    print(" " * 60)  # Clear the progress line

    if not reports:
        print("\n  [OK] Global scan complete - no findings detected.\n")
        return

    # Sort regions: highest severity first
    reports.sort(key=lambda x: (x.max_severity_rank, len(x.findings)), reverse=True)

    for r in reports:
        priority = next(k for k, v in SEVERITY_RANK.items() if v == r.max_severity_rank)
        print(f"\n{'─'*80}")
        print(f"  REGION: {r.region.upper()}  |  PRIORITY: {priority}")
        print(f"{'─'*80}")

        r.findings.sort(key=lambda x: SEVERITY_RANK[x['Risk']], reverse=True)
        for f in r.findings:
            print(f"\n  [{f['Risk']}] {f['Type']}")
            print(f"  Resource : {f['Resource']}")
            print(f"  Detail   : {f['Detail']}")
            print(f"  Fix      : {f['Remediation']}")

    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    main()
