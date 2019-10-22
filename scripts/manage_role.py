#!/usr/bin/env python2.7

import sys
import json
import boto3
import argparse
from botocore.exceptions import ClientError

# Create IAM client
iam = boto3.client('iam')

# Minimal Policy Definition
minimal_policy = {
    "Statement": [
        {
          "Action": [
            "autoscaling:Describe*",
            "cloudformation:DescribeStack*",
            "cloudformation:GetTemplate",
            "cloudformation:ListStack*",
            "cloudfront:Get*",
            "cloudfront:List*",
            "cloudwatch:Describe*",
            "config:DeliverConfigSnapshot",
            "config:Describe*",
            "config:Get*",
            "config:ListDiscoveredResources",
            "cur:DescribeReportDefinitions",
            "directconnect:Describe*",
            "dynamodb:ListTables",
            "ec2:Describe*",
            "elasticbeanstalk:Describe*",
            "elasticache:Describe*",
            "elasticloadbalancing:Describe*",
            "elasticmapreduce:DescribeJobFlows",
            "events:Describe*",
            "events:List*",
            "glacier:ListVaults",
            "guardduty:Get*",
            "guardduty:List*",
            "kinesis:Describe*",
            "kinesis:List*",
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListGrants",
            "kms:ListKeys",
            "kms:ListKeyPolicies",
            "kms:ListResourceTags",
            "lambda:List*",
            "logs:Describe*",
            "rds:Describe*",
            "rds:ListTagsForResource",
            "redshift:Describe*",
            "route53:GetHostedZone",
            "route53:ListHostedZones",
            "route53:ListResourceRecordSets",
            "sdb:DomainMetadata",
            "sdb:ListDomains",
            "sns:ListSubscriptions",
            "sns:ListSubscriptionsByTopic",
            "sns:ListTopics",
            "sns:GetEndpointAttributes",
            "sns:GetSubscriptionAttributes",
            "sns:GetTopicAttributes",
            "s3:ListAllMyBuckets",
            "s3:ListBucket",
            "s3:GetBucketLocation",
            "s3:GetBucket*",
            "s3:GetLifecycleConfiguration",
            "s3:GetObjectAcl",
            "s3:GetObjectVersionAcl",
            "tag:GetResources",
            "tag:GetTagKeys"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "EnabledDiscoveryOfVariousAWSServices"
        },
        {
          "Action": [
            "iam:ListRoles",
            "iam:GetRolePolicy",
            "iam:GetAccountSummary",
            "iam:GenerateCredentialReport"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "EnableInsightDiscovery"
        },
        {
          "Action": [
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetEventSelectors",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:ListPublicKeys",
            "cloudtrail:ListTags",
            "cloudtrail:LookupEvents"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "LimitedCloudTrail"
        },
        {
          "Action": [
            "sns:gettopicattributes",
            "sns:listtopics"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:sns:*:*:*",
          "Sid": "LimitedSNSForCloudTrail"
        },
        {
          "Action": [
            "sqs:GetQueueAttributes",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueUrl"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:sqs:*:*:outcomesbucket*",
          "Sid": "LimitedSQSForCloudTrail"
        },
        {
          "Action": [
            "sqs:ListQueues"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "BeAbleToListSQSForCloudTrail"
        }
      ],
      "Version": "2012-10-17"
    }

# Minimal Policy Definition
full_policy = {
    "Statement": [
        {
          "Action": [
            "autoscaling:Describe*",
            "cloudformation:DescribeStack*",
            "cloudformation:GetTemplate",
            "cloudformation:ListStack*",
            "cloudfront:Get*",
            "cloudfront:List*",
            "cloudwatch:Describe*",
            "config:DeliverConfigSnapshot",
            "config:Describe*",
            "config:Get*",
            "config:ListDiscoveredResources",
            "cur:DescribeReportDefinitions",
            "directconnect:Describe*",
            "dynamodb:ListTables",
            "ec2:Describe*",
            "elasticbeanstalk:Describe*",
            "elasticache:Describe*",
            "elasticloadbalancing:Describe*",
            "elasticmapreduce:DescribeJobFlows",
            "events:Describe*",
            "events:List*",
            "glacier:ListVaults",
            "guardduty:Get*",
            "guardduty:List*",
            "kinesis:Describe*",
            "kinesis:List*",
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:GetKeyRotationStatus",
            "kms:ListAliases",
            "kms:ListGrants",
            "kms:ListKeys",
            "kms:ListKeyPolicies",
            "kms:ListResourceTags",
            "lambda:List*",
            "logs:Describe*",
            "rds:Describe*",
            "rds:ListTagsForResource",
            "redshift:Describe*",
            "route53:GetHostedZone",
            "route53:ListHostedZones",
            "route53:ListResourceRecordSets",
            "sdb:DomainMetadata",
            "sdb:ListDomains",
            "sns:ListSubscriptions",
            "sns:ListSubscriptionsByTopic",
            "sns:ListTopics",
            "sns:GetEndpointAttributes",
            "sns:GetSubscriptionAttributes",
            "sns:GetTopicAttributes",
            "s3:ListAllMyBuckets",
            "s3:ListBucket",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:GetBucket*",
            "s3:GetLifecycleConfiguration",
            "s3:GetObjectAcl",
            "s3:GetObjectVersionAcl",
            "tag:GetResources",
            "tag:GetTagKeys"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "EnabledDiscoveryOfVariousAWSServices"
        },
        {
          "Action": [
            "iam:Get*",
            "iam:List*",
            "iam:ListRoles",
            "iam:GetRolePolicy",
            "iam:GetAccountSummary",
            "iam:GenerateCredentialReport"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "EnableInsightDiscovery"
        },
        {
          "Action": [
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetEventSelectors",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:ListPublicKeys",
            "cloudtrail:ListTags",
            "cloudtrail:LookupEvents",
            "cloudtrail:StartLogging",
            "cloudtrail:UpdateTrail"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "EnableCloudTrailIfAccountDoesntHaveCloudTrailsEnabled"
        },
        {
          "Action": [
            "s3:CreateBucket",
            "s3:PutBucketPolicy",
            "s3:DeleteBucket"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:s3:::outcomesbucket-*",
          "Sid": "CreateCloudTrailS3BucketIfCloudTrailsAreBeingSetupByAlertLogic"
        },
        {
          "Action": [
            "sns:CreateTopic",
            "sns:DeleteTopic"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:sns:*:*:outcomestopic",
          "Sid": "CreateCloudTrailsTopicTfOneWasntAlreadySetupForCloudTrails"
        },
        {
          "Action": [
            "sns:addpermission",
            "sns:gettopicattributes",
            "sns:listtopics",
            "sns:settopicattributes",
            "sns:subscribe"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:sns:*:*:*",
          "Sid": "MakeSureThatCloudTrailsSnsTopicIsSetupCorrectlyForCloudTrailPublishingAndSqsSubsription"
        },
        {
          "Action": [
            "sqs:CreateQueue",
            "sqs:DeleteQueue",
            "sqs:SetQueueAttributes",
            "sqs:GetQueueAttributes",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueUrl"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:sqs:*:*:outcomesbucket*",
          "Sid": "CreateAlertLogicSqsQueueToSubscribeToCloudTrailsSnsTopicNotifications"
        },
        {
          "Action": [
            "sqs:ListQueues"
          ],
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "BeAbleToListSQSForCloudTrail"
        },
        {
          "Action": [
            "ec2:GetConsoleOutput",
            "ec2:GetConsoleScreenShot",
            "ec2:StartInstances",
            "ec2:StopInstances",
            "ec2:TerminateInstances"
          ],
          "Condition": {
            "StringEquals": {
              "ec2:ResourceTag/AlertLogic": "Security"
            }
          },
          "Effect": "Allow",
          "Resource": "arn:aws:ec2:*:*:instance/*",
          "Sid": "EnableAlertLogicApplianceStateManagement"
        },
        {
          "Action": [
            "autoscaling:UpdateAutoScalingGroup"
          ],
          "Condition": {
            "StringEquals": {
              "ec2:ResourceTag/AlertLogic": "Security"
            }
          },
          "Effect": "Allow",
          "Resource": "arn:aws:autoscaling:*:*:autoScalingGroup/*",
          "Sid": "EnableAlertLogicAutoScalingGroupManagement"
        }
      ],
      "Version": "2012-10-17"
    }

def create_policy(policy_name, minimal):
    if minimal:
        response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(minimal_policy)
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully created IAM Policy: {}".format(response['Policy']['Arn']))
    else:
        response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(minimal_policy)
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully created IAM Policy: {}".format(response['Policy']['Arn']))

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

def update_policy(account, policy_name, minimal):
    # Get existing IAM policy
    policy_arn = 'arn:aws:iam::' + account + ':policy/' + policy_name
    if minimal:
        # Create the new version of the policy and set it as the default version
        try:
            response = iam.create_policy_version(PolicyArn=policy_arn,
                                                 PolicyDocument=json.dumps(minimal_policy),
                                                 SetAsDefault=True)
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print("Successfully updated IAM Policy: {}".format(policy_arn))
        except ClientError as e:
            print(e)
    else:
        # Create the new version of the policy and set it as the default version
        try:
            response = iam.create_policy_version(PolicyArn=policy_arn,
                                                 PolicyDocument=json.dumps(full_policy),
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
        description='IAM Policy Management for SIEMless Threat upgrade'
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
        print("Minimal permission option Allows you to maintain full control over the changes in your deployment, and requires you to perform any necessary actions manually.")
        yes_or_no("Continue applying minimal permissions policy?")
    else:
        print("Full permission option allows Alert Logic to make all the necessary changes to your AWS account")
        yes_or_no("Continue applying full permissions policy?")
    policy_name = args.policy_name
    if args.account:
        account = args.account
    if args.create:
        yes_or_no("Are you sure you want to create policy {}?".format(policy_name))
        create_policy(policy_name, minimal)
    if args.update:
        yes_or_no("Are you sure you want to update policy {}?".format(policy_name))
        update_policy(account, policy_name, minimal)
    if args.list_versions:
        list_policy_versions(account, policy_name)
    if args.delete_version:
        yes_or_no("Are you sure you want to delete policy {} version {}?".format(policy_name, args.delete_version))
        delete_policy_version(account, policy_name, args.delete_version)

if __name__ == '__main__':
    main(sys.argv)