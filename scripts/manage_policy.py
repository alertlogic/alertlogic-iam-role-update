#######################################
# Alert Logic IAM Policy Management
#
# Author: Justin Early <jearly@alertlogic.com>

import sys
import json
import boto3
import requests
import argparse
from botocore.exceptions import ClientError

# Create IAM client
iam = boto3.client('iam')

def get_policy(minimal):
    if minimal:
        policy_url = "https://docs.alertlogic.com/pdf-files/minimal.json"
    else:
        policy_url = "https://docs.alertlogic.com/pdf-files/full.json"
    try:
        policy = requests.get(policy_url)
        if policy.status_code == 200:
            return json.loads(policy.content)
        else:
            print("Error retrieving the policy document from Alert Logic. Please contact support.")
            sys.exit(1)
    except Exception as e:
        print(e)

def create_policy(policy_name, policy):
    try:
        response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy)
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully created IAM Policy: {}".format(response['Policy']['Arn']))
    except ClientError as e:
        print(e)

def list_policy_versions(account, policy_name):
    versions = []
    policy_arn = 'arn:aws:iam::' + account + ':policy/' + policy_name
    try:
        response = iam.list_policy_versions(
            PolicyArn=policy_arn
        )
        for version in response['Versions']:
            versions.append(version['VersionId'])
            if version['IsDefaultVersion'] == True:
                default_version = version['VersionId']
        print("Existing policy versions: {}".format(versions))
        print("Default policy version: {}".format(default_version))
    except ClientError as e:
        print(e)

def delete_policy_version(account, policy_name, version):
    policy_arn = 'arn:aws:iam::' + account + ':policy/' + policy_name
    try: 
        response = iam.delete_policy_version(
            PolicyArn=policy_arn,
            VersionId=version
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully deleted IAM Policy version: {}".format(version))
    except ClientError as e:
        print(e)

def update_policy(account, policy_name, policy):
    # Get existing IAM policy
    policy_arn = 'arn:aws:iam::' + account + ':policy/' + policy_name
    try: 
        # Create the new version of the policy and set it as the default version
        response = iam.create_policy_version(PolicyArn=policy_arn,
                                             PolicyDocument=json.dumps(policy),
                                             SetAsDefault=True)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print("Successfully updated IAM Policy: {}".format(policy_arn))
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
        description='Alert Logic IAM Policy Management'
    )
    parser.add_argument(
        '--policy-name',
        help='IAM policy name to create/update',
        dest='policy_name',
        type=str,
        required=True
    )
    parser.add_argument(
        '--account',
        help='AWS account number',
        dest='account',
        type=str
    )
    parser.add_argument(
        '--create',
        help='Create IAM policy',
        action='store_true',
        dest='create'
    )
    parser.add_argument(
        '--update',
        help='Update existing IAM policy',
        action="store_true",
        dest='update'
    )
    parser.add_argument(
        '--delete-version',
        help='IAM policy version to delete',
        dest='delete_version',
        type=str
    )
    parser.add_argument(
        '--list-versions',
        help='List existing IAM policy versions',
        action='store_true',
        dest='list_versions'
    )
    parser.add_argument(
        '--minimal',
        help='Apply minimal IAM policy',
        action="store_true",
        dest='minimal'
    )
    args = parser.parse_args()
    minimal = False
    if args.minimal:
        minimal = True
        print("Minimal permission option allows you to maintain full control over the changes in your deployment, and requires you to perform any necessary actions manually.")
        yes_or_no("Continue applying minimal permissions policy?")
        policy = get_policy(True)
    else:
        print("Full permission option allows Alert Logic to make all the necessary changes to your AWS account")
        yes_or_no("Continue applying full permissions policy?")
        policy = get_policy(False)
    policy_name = args.policy_name
    if args.account:
        account = args.account
    if args.create:
        yes_or_no("Are you sure you want to create IAM Policy {}?".format(policy_name))
        create_policy(policy_name, policy)
    if args.update:
        yes_or_no("Are you sure you want to update IAM Policy {}?".format(policy_name))
        update_policy(account, policy_name, policy)
    if args.list_versions:
        list_policy_versions(account, policy_name)
    if args.delete_version:
        yes_or_no("Are you sure you want to delete IAM Policy {} version {}?".format(policy_name, args.delete_version))
        delete_policy_version(account, policy_name, args.delete_version)

if __name__ == '__main__':
    main(sys.argv)