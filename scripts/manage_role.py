#######################################
# Alert Logic IAM Role Management
#
# Author: Justin Early <jearly@alertlogic.com>

import sys
import json
import boto3
import argparse
from botocore.exceptions import ClientError

# Create IAM client
iam = boto3.client('iam')

s3_cloudtrail = '239734009475'
us_account    = '733251395267'
uk_account    = '857795874556'

def create_role(role_name, description, trust_account, external_id, policy_arn):
    trust_arn = 'arn:aws:iam::' + trust_account + ':root'
    
    trust_policy={
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "AWS": trust_arn
          },
          "Action": "sts:AssumeRole",
          "Condition": {
            "StringEquals": {
              "sts:ExternalId": external_id
            }
          }
        }
      ]
    }
    
    try:
        # Create IAM Role
        response = iam.create_role(
            Path='/',
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description
        )
    
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully created IAM Role: {}".format(response['Role']['Arn']))
    except ClientError as e:
        print(e)

def attach_policy(role_name, policy_arn):
    try:
        # Attach a role policy
        response = iam.attach_role_policy(
            PolicyArn=policy_arn,
            RoleName=role_name
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully attached {} to IAM Role: {}".format(policy_arn, role_name))
    except ClientError as e:
        print(e)

def detach_policy(role_name, policy_arn):
    try:
        # Attach a role policy
        response = iam.detach_role_policy(
            PolicyArn=policy_arn,
            RoleName=role_name
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully detached {} from IAM Role: {}".format(policy_arn, role_name))
    except ClientError as e:
        print(e)

def delete_role(role_name):
    try:
        response = client.delete_role(
            RoleName=role_name
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print("Successfully deleted IAM Role: {}".format(role_name))
    except ClientError as e:
        print(e)

def yes_or_no(question):
    while "The answer is invalid":
        reply = str(raw_input(question+' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            sys.exit(0)

def main(_argv):
    parser = argparse.ArgumentParser(
        description='Alert Logic IAM Role Management'
    )
    parser.add_argument(
        '--role-name',
        help='IAM role name to create',
        dest='role_name',
        type=str,
        required=True
    )
    parser.add_argument(
        '--access-type',
        help="Options: ['log'(CloudTrail and S3 log collection only), 'us', 'uk']",
        dest='type',
        choices=['log','us','uk'],
        type=str
    )
    parser.add_argument(
        '--external-id',
        help="Alert Logic Customer ID. To find your Customer ID, in the Alert Logic console, click Settings > Support Information.",
        dest='external_id',
        type=str
    )
    parser.add_argument(
        '--policy-arn',
        help="Alert Logic IAM Policy previously created.",
        dest='policy_arn',
        type=str
    )
    parser.add_argument(
        '--create',
        help='Create IAM Role',
        action="store_true",
        dest='create'
    )
    parser.add_argument(
        '--delete',
        help='Delete IAM Role',
        action="store_true",
        dest='delete'
    )
    parser.add_argument(
        '--detach-policy',
        help='Detach IAM Policy from role',
        action="store_true",
        dest='detach_policy'
    )
    parser.add_argument(
        '--attach-policy',
        help='Attach IAM Policy from role',
        action="store_true",
        dest='attach_policy'
    )
    args = parser.parse_args()
    description = "Alert Logic cross-account access role"
    
    if args.create:
        if not all([args.type, args.external_id, args.role_name, args.policy_arn]):
            print("Required parameters: [--role-name, --external-id, --access-type, --policy-arn]")
            parser.print_help()
            sys.exit(1)
        else:
            if args.type == 'log':
                trust_account = s3_cloudtrail
            if args.type == 'us':
                trust_account = us_account
            if args.type == 'uk':
                trust_account = uk_account
        print("Alert Logic Customer ID(External ID): {}".format(args.external_id))
        print("IAM Role to be created: {}".format(args.role_name))
        print("IAM Policy Arn to be attached: {}".format(args.policy_arn))
        print("Alert Logic account for cross-account access: {}".format(trust_account))
        yes_or_no("Create new IAM Role {} and apply policy: {}?".format(args.role_name, args.policy_arn))
        create_role(args.role_name, description, trust_account, args.external_id, args.policy_arn)
    if args.delete:
        yes_or_no("Are you sure you want to delete role {}?".format(args.role_name))
        delete_role(args.role_name)
    if args.attach_policy:
        if not all([args.role_name, args.policy_arn]):
            print("Required parameters: [--role-name, --policy-arn]")
            parser.print_help()
            sys.exit(1)
        else:
            yes_or_no("Are you sure you want to attach policy {} to role {}?".format(args.policy_arn, args.role_name))
            attach_policy(args.role_name, args.policy_arn)
    if args.detach_policy:
        if not all([args.role_name, args.policy_arn]):
            print("Required parameters: [--role-name, --policy-arn]")
            parser.print_help()
            sys.exit(1)
        else:
            yes_or_no("Are you sure you want to detach policy {} from role {}?".format(args.policy_arn, args.role_name))
            detach_policy(args.role_name, args.policy_arn)
    
if __name__ == '__main__':
    main(sys.argv)