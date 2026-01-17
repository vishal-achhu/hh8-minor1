#!/usr/bin/env python3
"""
AWS Cloud Misconfiguration Scanner
Scans S3 buckets and IAM for security misconfigurations using Boto3
Cross-references findings against CIS AWS Foundations Benchmark
"""

import boto3
import json
import argparse
from datetime import datetime, timedelta
from typing import List, Dict
from botocore.exceptions import ClientError, NoCredentialsError


class SecurityFinding:
    """Represents a security finding"""
    def __init__(self, finding_id, severity, resource, resource_type, 
                 issue, description, recommendation, cis_reference):
        self.id = finding_id
        self.severity = severity
        self.resource = resource
        self.type = resource_type
        self.issue = issue
        self.description = description
        self.recommendation = recommendation
        self.cis_reference = cis_reference
        self.compliant = False

    def to_dict(self):
        return {
            'id': self.id,
            'severity': self.severity,
            'resource': self.resource,
            'type': self.type,
            'issue': self.issue,
            'description': self.description,
            'recommendation': self.recommendation,
            'cis_reference': self.cis_reference,
            'compliant': self.compliant
        }


class AWSSecurityScanner:
    """Main scanner class for AWS security auditing"""
    
    def __init__(self, access_key=None, secret_key=None, region='us-east-1'):
        """Initialize AWS clients"""
        try:
            if access_key and secret_key:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
                self.iam_client = boto3.client(
                    'iam',
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
            else:
                # Use default credentials from environment or ~/.aws/credentials
                self.s3_client = boto3.client('s3', region_name=region)
                self.iam_client = boto3.client('iam', region_name=region)
            
            self.region = region
            self.findings = []
            
        except NoCredentialsError:
            print("ERROR: No AWS credentials found. Please provide credentials or configure AWS CLI.")
            raise

    def scan_all(self):
        """Run all security scans"""
        print("=" * 70)
        print("AWS SECURITY MISCONFIGURATION SCANNER")
        print("=" * 70)
        print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Region: {self.region}\n")
        
        print("[*] Scanning S3 buckets...")
        self.scan_s3_buckets()
        
        print("[*] Scanning IAM configuration...")
        self.scan_iam()
        
        return self.generate_report()

    def scan_s3_buckets(self):
        """Scan all S3 buckets for misconfigurations"""
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            print(f"    Found {len(buckets)} S3 buckets to scan")
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                print(f"    Scanning bucket: {bucket_name}")
                
                # Check bucket ACL
                self._check_bucket_acl(bucket_name)
                
                # Check bucket policy
                self._check_bucket_policy(bucket_name)
                
                # Check bucket encryption
                self._check_bucket_encryption(bucket_name)
                
                # Check bucket versioning
                self._check_bucket_versioning(bucket_name)
                
                # Check public access block
                self._check_public_access_block(bucket_name)
                
        except ClientError as e:
            print(f"    ERROR scanning S3: {e}")

    def _check_bucket_acl(self, bucket_name):
        """Check for public ACL grants"""
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            
            public_uris = [
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            ]
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                uri = grantee.get('URI', '')
                
                if uri in public_uris:
                    permission = grant.get('Permission')
                    finding = SecurityFinding(
                        finding_id=f"S3-ACL-{bucket_name}",
                        severity='critical',
                        resource=bucket_name,
                        resource_type='S3 Bucket',
                        issue='Public ACL Grants',
                        description=f'Bucket ACL grants {permission} permission to {uri.split("/")[-1]}',
                        recommendation='Remove public ACL grants. Use bucket policies with specific principals instead.',
                        cis_reference='CIS AWS 2.1.5'
                    )
                    self.findings.append(finding)
                    
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"      Warning: Could not check ACL for {bucket_name}: {e}")

    def _check_bucket_policy(self, bucket_name):
        """Check for overly permissive bucket policies"""
        try:
            policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
            
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Check for wildcard principal
                is_public = False
                if principal == '*':
                    is_public = True
                elif isinstance(principal, dict):
                    if principal.get('AWS') == '*':
                        is_public = True
                
                if is_public and effect == 'Allow':
                    actions = statement.get('Action', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    
                    finding = SecurityFinding(
                        finding_id=f"S3-POLICY-{bucket_name}",
                        severity='critical',
                        resource=bucket_name,
                        resource_type='S3 Bucket',
                        issue='Public Bucket Policy',
                        description=f'Bucket policy allows public access with Principal: "*" for actions: {", ".join(actions)}',
                        recommendation='Restrict bucket policy to specific AWS principals. Add condition keys to limit access.',
                        cis_reference='CIS AWS 2.1.5'
                    )
                    self.findings.append(finding)
                    break
                    
        except ClientError as e:
            if e.response['Error']['Code'] not in ['NoSuchBucketPolicy', 'AccessDenied']:
                print(f"      Warning: Could not check policy for {bucket_name}: {e}")

    def _check_bucket_encryption(self, bucket_name):
        """Check if bucket has encryption enabled"""
        try:
            self.s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                finding = SecurityFinding(
                    finding_id=f"S3-ENC-{bucket_name}",
                    severity='high',
                    resource=bucket_name,
                    resource_type='S3 Bucket',
                    issue='Encryption Not Enabled',
                    description='S3 bucket does not have default encryption configured',
                    recommendation='Enable default encryption using SSE-S3, SSE-KMS, or SSE-C',
                    cis_reference='CIS AWS 2.1.1'
                )
                self.findings.append(finding)

    def _check_bucket_versioning(self, bucket_name):
        """Check if bucket has versioning enabled"""
        try:
            versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            
            if status != 'Enabled':
                finding = SecurityFinding(
                    finding_id=f"S3-VER-{bucket_name}",
                    severity='medium',
                    resource=bucket_name,
                    resource_type='S3 Bucket',
                    issue='Versioning Not Enabled',
                    description='S3 bucket versioning is disabled',
                    recommendation='Enable versioning to protect against accidental deletion and for compliance requirements',
                    cis_reference='CIS AWS 2.1.3'
                )
                self.findings.append(finding)
                
        except ClientError as e:
            print(f"      Warning: Could not check versioning for {bucket_name}: {e}")

    def _check_public_access_block(self, bucket_name):
        """Check if public access block is configured"""
        try:
            pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = pab.get('PublicAccessBlockConfiguration', {})
            
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                finding = SecurityFinding(
                    finding_id=f"S3-PAB-{bucket_name}",
                    severity='high',
                    resource=bucket_name,
                    resource_type='S3 Bucket',
                    issue='Public Access Block Not Fully Configured',
                    description='S3 bucket does not have all public access block settings enabled',
                    recommendation='Enable all four public access block settings unless public access is explicitly required',
                    cis_reference='CIS AWS 2.1.5'
                )
                self.findings.append(finding)
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                finding = SecurityFinding(
                    finding_id=f"S3-PAB-{bucket_name}",
                    severity='high',
                    resource=bucket_name,
                    resource_type='S3 Bucket',
                    issue='No Public Access Block Configuration',
                    description='S3 bucket has no public access block configuration',
                    recommendation='Configure public access block settings to prevent accidental public exposure',
                    cis_reference='CIS AWS 2.1.5'
                )
                self.findings.append(finding)

    def scan_iam(self):
        """Scan IAM for security issues"""
        try:
            # Check root account
            self._check_root_account()
            
            # Check IAM users
            self._check_iam_users()
            
            # Check IAM policies
            self._check_iam_policies()
            
            # Check password policy
            self._check_password_policy()
            
        except ClientError as e:
            print(f"    ERROR scanning IAM: {e}")

    def _check_root_account(self):
        """Check root account security"""
        try:
            summary = self.iam_client.get_account_summary()
            summary_map = summary.get('SummaryMap', {})
            
            # Check for root access keys
            if summary_map.get('AccountAccessKeysPresent', 0) > 0:
                finding = SecurityFinding(
                    finding_id='IAM-ROOT-KEYS',
                    severity='critical',
                    resource='Root Account',
                    resource_type='IAM Account',
                    issue='Root Account Has Access Keys',
                    description='Root account has active access keys',
                    recommendation='Delete root access keys immediately. Use IAM users with appropriate permissions instead.',
                    cis_reference='CIS AWS 1.4'
                )
                self.findings.append(finding)
                
            # Check root MFA
            if summary_map.get('AccountMFAEnabled', 0) == 0:
                finding = SecurityFinding(
                    finding_id='IAM-ROOT-MFA',
                    severity='critical',
                    resource='Root Account',
                    resource_type='IAM Account',
                    issue='Root Account MFA Not Enabled',
                    description='Root account does not have MFA enabled',
                    recommendation='Enable virtual or hardware MFA for the root account immediately.',
                    cis_reference='CIS AWS 1.5'
                )
                self.findings.append(finding)
                
        except ClientError as e:
            print(f"      Warning: Could not check root account: {e}")

    def _check_iam_users(self):
        """Check IAM users for security issues"""
        try:
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    # Check MFA
                    try:
                        mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                        if len(mfa_devices.get('MFADevices', [])) == 0:
                            # Check if user has console access
                            try:
                                self.iam_client.get_login_profile(UserName=username)
                                finding = SecurityFinding(
                                    finding_id=f"IAM-MFA-{username}",
                                    severity='high',
                                    resource=username,
                                    resource_type='IAM User',
                                    issue='MFA Not Enabled',
                                    description='IAM user with console access does not have MFA enabled',
                                    recommendation='Enable virtual or hardware MFA for this user',
                                    cis_reference='CIS AWS 1.2'
                                )
                                self.findings.append(finding)
                            except ClientError:
                                pass  # No console access
                    except ClientError:
                        pass
                    
                    # Check access key age
                    try:
                        keys = self.iam_client.list_access_keys(UserName=username)
                        for key in keys.get('AccessKeyMetadata', []):
                            key_age = datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']
                            if key_age > timedelta(days=90):
                                finding = SecurityFinding(
                                    finding_id=f"IAM-KEY-AGE-{username}-{key['AccessKeyId']}",
                                    severity='medium',
                                    resource=f"{username} ({key['AccessKeyId']})",
                                    resource_type='IAM Access Key',
                                    issue='Access Key Over 90 Days Old',
                                    description=f'Access key is {key_age.days} days old',
                                    recommendation='Rotate access keys every 90 days',
                                    cis_reference='CIS AWS 1.3'
                                )
                                self.findings.append(finding)
                    except ClientError:
                        pass
                        
        except ClientError as e:
            print(f"      Warning: Could not check IAM users: {e}")

    def _check_iam_policies(self):
        """Check for overly permissive IAM policies"""
        try:
            paginator = self.iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                for policy in page['Policies']:
                    try:
                        version = self.iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        document = version['PolicyVersion']['Document']
                        statements = document.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        
                        for statement in statements:
                            if statement.get('Effect') != 'Allow':
                                continue
                            
                            actions = statement.get('Action', [])
                            if not isinstance(actions, list):
                                actions = [actions]
                            
                            resources = statement.get('Resource', [])
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            # Check for wildcard permissions
                            has_wildcard_action = '*' in actions
                            has_wildcard_resource = '*' in resources
                            
                            if has_wildcard_action and has_wildcard_resource:
                                finding = SecurityFinding(
                                    finding_id=f"IAM-POLICY-{policy['PolicyName']}",
                                    severity='high',
                                    resource=policy['PolicyName'],
                                    resource_type='IAM Policy',
                                    issue='Overly Permissive Policy',
                                    description='Policy grants wildcard (*) permissions on all resources',
                                    recommendation='Apply principle of least privilege. Specify exact actions and resources needed.',
                                    cis_reference='CIS AWS 1.16'
                                )
                                self.findings.append(finding)
                                break
                                
                    except ClientError:
                        pass
                        
        except ClientError as e:
            print(f"      Warning: Could not check IAM policies: {e}")

    def _check_password_policy(self):
        """Check IAM password policy"""
        try:
            policy = self.iam_client.get_account_password_policy()
            pp = policy.get('PasswordPolicy', {})
            
            issues = []
            if pp.get('MinimumPasswordLength', 0) < 14:
                issues.append('minimum length < 14')
            if not pp.get('RequireUppercaseCharacters', False):
                issues.append('no uppercase requirement')
            if not pp.get('RequireLowercaseCharacters', False):
                issues.append('no lowercase requirement')
            if not pp.get('RequireNumbers', False):
                issues.append('no number requirement')
            if not pp.get('RequireSymbols', False):
                issues.append('no symbol requirement')
            if pp.get('MaxPasswordAge', 0) == 0 or pp.get('MaxPasswordAge', 0) > 90:
                issues.append('password expiry > 90 days or disabled')
            
            if issues:
                finding = SecurityFinding(
                    finding_id='IAM-PASSWORD-POLICY',
                    severity='medium',
                    resource='Account Password Policy',
                    resource_type='IAM Password Policy',
                    issue='Weak Password Policy',
                    description=f'Password policy does not meet best practices: {", ".join(issues)}',
                    recommendation='Configure password policy with: min 14 chars, require upper/lower/numbers/symbols, 90 day expiry',
                    cis_reference='CIS AWS 1.5-1.11'
                )
                self.findings.append(finding)
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                finding = SecurityFinding(
                    finding_id='IAM-PASSWORD-POLICY',
                    severity='high',
                    resource='Account Password Policy',
                    resource_type='IAM Password Policy',
                    issue='No Password Policy Configured',
                    description='Account does not have a password policy configured',
                    recommendation='Create a password policy that meets CIS requirements',
                    cis_reference='CIS AWS 1.5-1.11'
                )
                self.findings.append(finding)

    def generate_report(self):
        """Generate and display the security report"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for finding in self.findings:
            summary[finding.severity] += 1
        
        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Critical: {summary['critical']}")
        print(f"High:     {summary['high']}")
        print(f"Medium:   {summary['medium']}")
        print(f"Low:      {summary['low']}")
        print(f"Total:    {len(self.findings)}")
        
        if self.findings:
            print("\n" + "=" * 70)
            print("FINDINGS")
            print("=" * 70)
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sorted_findings = sorted(self.findings, key=lambda x: severity_order[x.severity])
            
            for finding in sorted_findings:
                print(f"\n[{finding.severity.upper()}] {finding.issue}")
                print(f"  Resource: {finding.resource} ({finding.type})")
                print(f"  Description: {finding.description}")
                print(f"  Recommendation: {finding.recommendation}")
                print(f"  CIS Reference: {finding.cis_reference}")
        else:
            print("\n✓ No security issues found!")
        
        # Generate JSON report
        report = {
            'scan_date': datetime.now().isoformat(),
            'region': self.region,
            'summary': summary,
            'findings': [f.to_dict() for f in self.findings]
        }
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='AWS Cloud Misconfiguration Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Use default AWS credentials
  python scanner.py

  # Specify credentials
  python scanner.py --access-key AKIA... --secret-key ...

  # Specify region
  python scanner.py --region us-west-2

  # Export results to JSON
  python scanner.py --output report.json
        '''
    )
    
    parser.add_argument('--access-key', help='AWS Access Key ID')
    parser.add_argument('--secret-key', help='AWS Secret Access Key')
    parser.add_argument('--region', default='us-east-1', help='AWS Region (default: us-east-1)')
    parser.add_argument('--output', '-o', help='Output JSON file for results')
    
    args = parser.parse_args()
    
    try:
        scanner = AWSSecurityScanner(
            access_key=args.access_key,
            secret_key=args.secret_key,
            region=args.region
        )
        
        report = scanner.scan_all()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n[*] Report saved to: {args.output}")
        
        print("\n" + "=" * 70)
        print("Scan completed at:", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        print("=" * 70)
        
    except Exception as e:
        print(f"\nERROR: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())