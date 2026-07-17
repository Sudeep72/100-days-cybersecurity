#!/usr/bin/env python3
"""
Day 075 - Cloud Enumeration Tool
100 Days of Cybersecurity by Sudeep Ravichandran

Enumerate AWS, Azure, GCP resources for pen testing.
Requires appropriate credentials and authorization.

Usage:
    python3 cloud_enum.py --provider aws --profile default
    python3 cloud_enum.py --provider azure --subscription-id xxxxx
    python3 cloud_enum.py --provider gcp --project my-project
"""

import boto3
import json
import argparse
from datetime import datetime
from typing import Dict, List

class CloudEnumerator:
    def __init__(self, provider: str, **kwargs):
        self.provider = provider
        self.findings = {
            "timestamp": datetime.utcnow().isoformat(),
            "provider": provider,
            "resources": {
                "storage": [],
                "compute": [],
                "database": [],
                "networking": [],
                "iam": [],
                "logs": []
            }
        }
        
        if provider == "aws":
            self.session = boto3.Session(profile_name=kwargs.get("profile", "default"))
        elif provider == "azure":
            self.subscription_id = kwargs.get("subscription_id")
        elif provider == "gcp":
            self.project_id = kwargs.get("project_id")

    def enumerate_aws(self) -> Dict:
        """Enumerate AWS resources"""
        print("[*] Starting AWS enumeration...")
        
        # S3 Buckets
        self._enumerate_s3_buckets()
        
        # EC2 Instances
        self._enumerate_ec2_instances()
        
        # RDS Databases
        self._enumerate_rds_databases()
        
        # IAM Users & Roles
        self._enumerate_iam()
        
        # CloudTrail
        self._enumerate_cloudtrail()
        
        # VPCs & Security Groups
        self._enumerate_networking()
        
        return self.findings

    def _enumerate_s3_buckets(self):
        """Enumerate S3 buckets and their configurations"""
        print("[*] Enumerating S3 buckets...")
        
        s3 = self.session.client('s3')
        
        try:
            response = s3.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                bucket_info = {
                    "name": bucket_name,
                    "creation_date": bucket['CreationDate'].isoformat(),
                    "public": False,
                    "encrypted": False,
                    "versioning": False,
                    "logging": False,
                    "access_log": None
                }
                
                # Check if bucket is public
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                            bucket_info['public'] = True
                            print(f"[!] PUBLIC BUCKET FOUND: {bucket_name}")
                except Exception as e:
                    print(f"[!] Error checking ACL for {bucket_name}: {str(e)}")
                
                # Check encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    bucket_info['encrypted'] = True
                except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    bucket_info['encrypted'] = False
                except Exception as e:
                    print(f"[!] Error checking encryption for {bucket_name}: {str(e)}")
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    bucket_info['versioning'] = versioning.get('Status') == 'Enabled'
                except Exception as e:
                    print(f"[!] Error checking versioning for {bucket_name}: {str(e)}")
                
                # Check logging
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                    if logging.get('LoggingEnabled'):
                        bucket_info['logging'] = True
                        bucket_info['access_log'] = logging['LoggingEnabled']['TargetBucket']
                except Exception as e:
                    print(f"[!] Error checking logging for {bucket_name}: {str(e)}")
                
                self.findings['resources']['storage'].append(bucket_info)
                print(f"[+] Found bucket: {bucket_name} (Public: {bucket_info['public']})")
        
        except Exception as e:
            print(f"[!] Error enumerating S3 buckets: {str(e)}")

    def _enumerate_ec2_instances(self):
        """Enumerate EC2 instances"""
        print("[*] Enumerating EC2 instances...")
        
        ec2 = self.session.client('ec2')
        
        try:
            response = ec2.describe_instances()
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_info = {
                        "instance_id": instance['InstanceId'],
                        "state": instance['State']['Name'],
                        "instance_type": instance.get('InstanceType'),
                        "public_ip": instance.get('PublicIpAddress'),
                        "private_ip": instance['PrivateIpAddress'],
                        "security_groups": [sg['GroupName'] for sg in instance.get('SecurityGroups', [])],
                        "iam_role": None,
                        "ebs_encrypted": False,
                        "monitoring": instance.get('Monitoring', {}).get('State', 'disabled')
                    }
                    
                    # Check IAM role
                    if 'IamInstanceProfile' in instance:
                        instance_info['iam_role'] = instance['IamInstanceProfile']['Arn']
                    
                    # Check EBS encryption
                    try:
                        for mapping in instance.get('BlockDeviceMappings', []):
                            if 'Ebs' in mapping:
                                volume_id = mapping['Ebs']['VolumeId']
                                volumes = ec2.describe_volumes(VolumeIds=[volume_id])
                                for vol in volumes.get('Volumes', []):
                                    if vol.get('Encrypted'):
                                        instance_info['ebs_encrypted'] = True
                    except Exception as e:
                        print(f"[!] Error checking EBS for {instance['InstanceId']}: {str(e)}")
                    
                    self.findings['resources']['compute'].append(instance_info)
                    print(f"[+] Found instance: {instance['InstanceId']} ({instance['InstanceType']})")
        
        except Exception as e:
            print(f"[!] Error enumerating EC2 instances: {str(e)}")

    def _enumerate_rds_databases(self):
        """Enumerate RDS databases"""
        print("[*] Enumerating RDS databases...")
        
        rds = self.session.client('rds')
        
        try:
            response = rds.describe_db_instances()
            
            for db in response.get('DBInstances', []):
                db_info = {
                    "identifier": db['DBInstanceIdentifier'],
                    "engine": db['Engine'],
                    "allocated_storage": db.get('AllocatedStorage'),
                    "multi_az": db.get('MultiAZ'),
                    "publicly_accessible": db.get('PubliclyAccessible'),
                    "encrypted": db.get('StorageEncrypted'),
                    "backup_retention": db.get('BackupRetentionPeriod'),
                    "endpoint": db.get('Endpoint', {}).get('Address'),
                    "master_username": db.get('MasterUsername')
                }
                
                self.findings['resources']['database'].append(db_info)
                print(f"[+] Found database: {db['DBInstanceIdentifier']} ({db['Engine']})")
                
                if db.get('PubliclyAccessible'):
                    print(f"[!] PUBLICLY ACCESSIBLE DATABASE: {db['DBInstanceIdentifier']}")
                
                if not db.get('StorageEncrypted'):
                    print(f"[!] UNENCRYPTED DATABASE: {db['DBInstanceIdentifier']}")
        
        except Exception as e:
            print(f"[!] Error enumerating RDS databases: {str(e)}")

    def _enumerate_iam(self):
        """Enumerate IAM users and roles"""
        print("[*] Enumerating IAM users and roles...")
        
        iam = self.session.client('iam')
        
        try:
            # Get current user
            sts = self.session.client('sts')
            current_identity = sts.get_caller_identity()
            self.findings['resources']['iam'].append({
                "type": "current_identity",
                "account_id": current_identity['Account'],
                "arn": current_identity['Arn'],
                "user_id": current_identity['UserId']
            })
            print(f"[+] Current identity: {current_identity['Arn']}")
            
            # List all users
            users = iam.list_users()
            for user in users.get('Users', []):
                user_info = {
                    "type": "user",
                    "username": user['UserName'],
                    "arn": user['Arn'],
                    "created": user['CreateDate'].isoformat(),
                    "mfa_devices": []
                }
                
                # Check for access keys
                try:
                    access_keys = iam.list_access_keys(UserName=user['UserName'])
                    user_info['access_keys_count'] = len(access_keys.get('AccessKeyMetadata', []))
                except Exception as e:
                    print(f"[!] Error checking access keys for {user['UserName']}: {str(e)}")
                
                # Check MFA
                try:
                    mfa = iam.list_mfa_devices(UserName=user['UserName'])
                    user_info['mfa_devices'] = [d['SerialNumber'] for d in mfa.get('MFADevices', [])]
                except Exception as e:
                    print(f"[!] Error checking MFA for {user['UserName']}: {str(e)}")
                
                self.findings['resources']['iam'].append(user_info)
                print(f"[+] Found user: {user['UserName']}")
            
            # List all roles
            roles = iam.list_roles()
            for role in roles.get('Roles', []):
                role_info = {
                    "type": "role",
                    "name": role['RoleName'],
                    "arn": role['Arn'],
                    "created": role['CreateDate'].isoformat(),
                    "assume_role_policy": role.get('AssumeRolePolicyDocument')
                }
                
                self.findings['resources']['iam'].append(role_info)
                print(f"[+] Found role: {role['RoleName']}")
        
        except Exception as e:
            print(f"[!] Error enumerating IAM: {str(e)}")

    def _enumerate_cloudtrail(self):
        """Enumerate CloudTrail configuration"""
        print("[*] Enumerating CloudTrail...")
        
        cloudtrail = self.session.client('cloudtrail')
        
        try:
            trails = cloudtrail.describe_trails()
            
            for trail in trails.get('trailList', []):
                trail_info = {
                    "name": trail['Name'],
                    "s3_bucket": trail.get('S3BucketName'),
                    "is_multi_region": trail.get('IsMultiRegionTrail'),
                    "is_organization_trail": trail.get('IsOrganizationTrail'),
                    "log_file_validation": trail.get('HasCustomEventSelectors'),
                    "status": None
                }
                
                # Check if logging is enabled
                try:
                    status = cloudtrail.get_trail_status(Name=trail['TrailArn'])
                    trail_info['status'] = status.get('IsLogging')
                except Exception as e:
                    print(f"[!] Error checking trail status for {trail['Name']}: {str(e)}")
                
                self.findings['resources']['logs'].append(trail_info)
                print(f"[+] Found CloudTrail: {trail['Name']} (Logging: {trail_info['status']})")
                
                if not trail_info['status']:
                    print(f"[!] CLOUDTRAIL NOT LOGGING: {trail['Name']}")
        
        except Exception as e:
            print(f"[!] Error enumerating CloudTrail: {str(e)}")

    def _enumerate_networking(self):
        """Enumerate VPCs and security groups"""
        print("[*] Enumerating networking...")
        
        ec2 = self.session.client('ec2')
        
        try:
            # VPCs
            vpcs = ec2.describe_vpcs()
            for vpc in vpcs.get('Vpcs', []):
                vpc_info = {
                    "vpc_id": vpc['VpcId'],
                    "cidr_block": vpc['CidrBlock'],
                    "is_default": vpc.get('IsDefault'),
                    "state": vpc.get('State'),
                    "subnets": []
                }
                self.findings['resources']['networking'].append(vpc_info)
                print(f"[+] Found VPC: {vpc['VpcId']}")
            
            # Security Groups
            sgs = ec2.describe_security_groups()
            for sg in sgs.get('SecurityGroups', []):
                sg_info = {
                    "group_id": sg['GroupId'],
                    "group_name": sg['GroupName'],
                    "vpc_id": sg.get('VpcId'),
                    "rules_inbound": len(sg.get('IpPermissions', [])),
                    "rules_outbound": len(sg.get('IpPermissionsEgress', [])),
                    "risky_rules": []
                }
                
                # Check for risky rules (open to 0.0.0.0/0)
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            sg_info['risky_rules'].append({
                                "protocol": rule.get('IpProtocol'),
                                "from_port": rule.get('FromPort'),
                                "to_port": rule.get('ToPort'),
                                "cidr": "0.0.0.0/0"
                            })
                
                self.findings['resources']['networking'].append(sg_info)
                
                if sg_info['risky_rules']:
                    print(f"[!] RISKY SECURITY GROUP: {sg['GroupId']} - Open to 0.0.0.0/0")
        
        except Exception as e:
            print(f"[!] Error enumerating networking: {str(e)}")

    def export_findings(self, filename: str = None):
        """Export findings to JSON file"""
        if filename is None:
            filename = f"cloud_enum_{self.provider}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        print(f"\n[+] Findings exported to {filename}")
        
        # Print summary
        print("\n[*] ENUMERATION SUMMARY:")
        print(f"├─ Storage resources: {len(self.findings['resources']['storage'])}")
        print(f"├─ Compute resources: {len(self.findings['resources']['compute'])}")
        print(f"├─ Database resources: {len(self.findings['resources']['database'])}")
        print(f"├─ Networking resources: {len(self.findings['resources']['networking'])}")
        print(f"├─ IAM resources: {len(self.findings['resources']['iam'])}")
        print(f"└─ Logging resources: {len(self.findings['resources']['logs'])}")


def main():
    parser = argparse.ArgumentParser(description='Cloud Resource Enumeration Tool - Day 075')
    parser.add_argument('--provider', choices=['aws', 'azure', 'gcp'], required=True, help='Cloud provider')
    parser.add_argument('--profile', help='AWS profile name (for AWS)')
    parser.add_argument('--subscription-id', help='Azure subscription ID')
    parser.add_argument('--project-id', help='GCP project ID')
    parser.add_argument('--output', help='Output file for findings (JSON)')
    
    args = parser.parse_args()
    
    print("[*] Cloud Enumeration Tool - Day 075")
    print("[*] Requires authorization. Ensure you have permission to enumerate.")
    print()
    
    if args.provider == "aws":
        enumerator = CloudEnumerator("aws", profile=args.profile)
        enumerator.enumerate_aws()
        enumerator.export_findings(args.output)
    elif args.provider == "azure":
        print("[!] Azure enumeration not yet implemented")
    elif args.provider == "gcp":
        print("[!] GCP enumeration not yet implemented")


if __name__ == "__main__":
    main()