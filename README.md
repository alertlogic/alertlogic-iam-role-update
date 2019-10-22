# Alert Logic IAM Management

These scripts provide a programatic method to create, update, or delete your Alert Logic IAM roles in order to deploy Alert Logic products into your AWS account.

## IAM Role Management Utility

### Usage:

Help:
```
python manage_role.py --help
usage: manage_role.py [-h] --role-name ROLE_NAME
                          [--access-type {log,us,uk}]
                          [--external-id EXTERNAL_ID]
                          [--policy-arn POLICY_ARN] [--create] [--delete]
                          [--detach-policy] [--attach-policy]

Alert Logic IAM Role Management

optional arguments:
  -h, --help            show this help message and exit
  --role-name ROLE_NAME IAM role name to create
  --access-type {log,us,uk} Options: ['log'(CloudTrail and S3 log collection only), 'us', 'uk']
  --external-id EXTERNAL_ID Alert Logic Customer ID. To find your Customer ID, in
                        the Alert Logic console, click Settings > Support Information.
  --policy-arn POLICY_ARN Alert Logic IAM Policy previously created.
  --create              Create IAM Role
  --delete              Delete IAM Role
  --detach-policy       Detach IAM Policy from role
  --attach-policy       Attach IAM Policy from role
```

Create role and attach existing policy:
```
python manage_role.py --role-name alertlogic-role  --external-id 1234567890 --policy-arn arn:aws:iam::123456789012345:policy/alertlogic-policy --create --access-type us
Alert Logic Customer ID(External ID): 1234567890
IAM Role to be created: alertlogic-role
IAM Policy Arn to be attached: arn:aws:iam::123456789012345:policy/alertlogic-policy
Alert Logic account for cross-account access: us: 123456789012345
Create new IAM Role alertlogic-role and apply policy: arn:aws:iam::123456789012345:policy/alertlogic-policy? (y/n): y
Successfully created IAM Role: alertlogic-role
```

Delete role:
```
python manage_role.py --role-name alertlogic-role --delete
Are you sure you want to delete role alertlogic-role? (y/n): y
Successfully deleted IAM Role: alertlogic-role
```

Attach policy to existing role:
```
python manage_role.py --role-name alertlogic-role --policy-arn arn:aws:iam::1234567890:policy/alertlogic-policy --attach-policy
Are you sure you want to attach policy arn:aws:iam::1234567890:policy/alertlogic-policy to IAM Role: alertlogic-role? (y/n): y
Successfully attached arn:aws:iam::1234567890:policy/alertlogic-policy to IAM Role: alertlogic-role
```

Detach policy to existing role:
```
python manage_role.py --role-name alertlogic-role --policy-arn arn:aws:iam::1234567890:policy/alertlogic-policy --detach-policy
Are you sure you want to detach policy arn:aws:iam::1234567890:policy/alertlogic-policy from IAM Role: alertlogic-role? (y/n): y
Successfully detached arn:aws:iam::1234567890:policy/alertlogic-policy from IAM Role: alertlogic-role
```

## IAM Policy Management Utility

### Usage:

Help:
```
python manage_policy.py --help
usage: manage_policy.py [-h] --policy-name POLICY_NAME [--account ACCOUNT]
                            [--create] [--update]
                            [--delete-version DELETE_VERSION]
                            [--list-versions] [--minimal]

Alert Logic IAM Policy Management

optional arguments:
  -h, --help            show this help message and exit
  --policy-name POLICY_NAME IAM policy name to create/update
  --account ACCOUNT     AWS account number
  --create              Create IAM policy
  --update              Update existing IAM policy
  --delete-version DELETE_VERSION IAM policy version to delete
  --list-versions       List existing IAM policy versions
  --minimal             Apply minimal IAM policy
```

Create minimal permission policy:
```
python manage_policy.py --policy-name alertlogic-policy --create --minimal
Minimal permission option Allows you to maintain full control over the changes in your deployment, and requires you to perform any necessary actions manually.
Continue applying minimal permissions policy? (y/n): y
Are you sure you want to create policy alertlogic-policy? (y/n): y
Successfully created IAM Policy: alertlogic-policy
```

Create full permission policy:
```
python manage_policy.py --policy-name alertlogic-policy --create
Full permission option allows Alert Logic to make all the necessary changes to your AWS account.
Continue applying full permissions policy? (y/n): y
Are you sure you want to create policy alertlogic-policy? (y/n): y
Successfully created IAM Policy: alertlogic-policy
```

Update existing policy to minimal permission:
```
python manage_policy.py --policy-name alertlogic-policy --update --account 1234567890 --minimal
Are you sure you want to update IAM Policy: alertlogic-policy? (y/n): y
Successfully updated IAM Policy: alertlogic-policy
```

Update existing policy to full permission:
```
python manage_policy.py --policy-name alertlogic-policy --update --account 1234567890
Are you sure you want to update IAM Policy: alertlogic-policy? (y/n): y
Successfully updated IAM Policy: alertlogic-policy
```

List policy versions:
```
python manage_iam.py --policy-name alertlogic-policy --account 1234567890 --list-versions
Existing policy versions: ['v8', 'v7', 'v6', 'v5', 'v4']
Default policy version: v8
```

Delete policy by version:
```
python manage_iam.py --policy-name alertlogic-policy --account 1234567890 --delete-version v4
Are you sure you want to delete policy alertlogic-policy version v4? (y/n): y
Successfully deleted IAM Policy version: v4
```

Contributing
------------

1. Fork the repository on Github
2. Create a named feature branch (like `add_component_x`)
3. Write your change
4. Submit a Pull Request using Github

License and Authors
-------------------
License:
Distributed under the MIT license.

Authors: 
Justin Early (jearly@alertlogic.com)
