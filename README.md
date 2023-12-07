[comment]: # "Auto-generated SOAR connector documentation"
# AWS Inspector

Publisher: Splunk  
Connector Version: 2.2.11  
Product Vendor: AWS  
Product Name: Inspector  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.2.0  

This app integrates with AWS Inspector to perform security assessment actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2019-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Asset Configuration

There are two ways to configure an AWS Inspector asset. The first is to configure the **access_key**
, **secret_key** and **region** variables. If it is preferred to use a role and Phantom is running
as an EC2 instance, the **use_role** checkbox can be checked instead. This will allow the role that
is attached to the instance to be used. Please see the [AWS EC2 and IAM
documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
for more information.

## Assumed Role Credentials

The optional **credentials** action parameter consists of temporary **assumed role** credentials
that will be used to perform the action instead of those that are configured in the **asset** . The
parameter is not designed to be configured manually, but should instead be used in conjunction with
the Phantom AWS Security Token Service app. The output of the **assume_role** action of the STS app
with data path **assume_role\_\<number>:action_result.data.\*.Credentials** consists of a dictionary
containing the **AccessKeyId** , **SecretAccessKey** , **SessionToken** and **Expiration** key/value
pairs. This dictionary can be passed directly into the credentials parameter in any of the following
actions within a playbook. For more information, please see the [AWS Identity and Access Management
documentation](https://docs.aws.amazon.com/iam/index.html) .


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Inspector asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**access_key** |  optional  | password | Access Key
**secret_key** |  optional  | password | Secret Key
**region** |  required  | string | Default Region
**use_role** |  optional  | boolean | Use attached role when running Phantom in EC2

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[add target](#action-add-target) - Create a new assessment target using the ARN of the resource group  
[delete target](#action-delete-target) - Delete the assessment target  
[list templates](#action-list-templates) - List the assessment templates of assessment targets  
[list targets](#action-list-targets) - List the assessment target ARNs within the AWS account  
[run assessment](#action-run-assessment) - Start the assessment run specified by the assessment template ARN  
[get findings](#action-get-findings) - List and describe the findings generated by the assessment runs  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'add target'
Create a new assessment target using the ARN of the resource group

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**target_name** |  required  | Name of the target | string |  `aws inspector target name` 
**resource_group_arn** |  optional  | Resource Group ARN used for creating the assessment target | string |  `aws inspector resource group arn`  `aws arn` 
**credentials** |  optional  | Assumed role credentials | string |  `aws credentials` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.resource_group_arn | string |  `aws inspector resource group arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:resourcegroup/0-He7VMMwP 
action_result.parameter.target_name | string |  `aws inspector target name`  |   test_target 
action_result.data.\*.assessmentTargetArn | string |  `aws inspector target arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K 
action_result.summary.total_target_arn | numeric |  |   1 
action_result.message | string |  |   Target successfully added 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.credentials | string |  `aws credentials`  |   {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Expiration': '2021-06-07 22:28:04', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SessionToken': 'EXAMPLEKEYTEST///////////wEaDFRU0s4AVrw0k0oYICK4ATAzOqzAkg9bHY29lYmP59UvVOHjLufOy4s7SnAzOxGqGIXnukLis4TWNhrJl5R5nYyimrm6K/9d0Cw2SWEXAMPLEEJHWJ+yY5Qk2QpWctS2BGn4n+G8cD6zEweCCMj+ScI5p8n7YI4wOdvXvOsVMmjV6F09Ujqr1w+NwoKXlglznXGs/7Q1kNZOMiioEhGUyoiHbQb37GCKslDK+oqe0KNaUKQ96YCepaLgMbMquDgdAM8I0TTxUO0o5ILF/gUyLT04R7QlOfktkdh6Qt0atTSEXAMPLEKEYTESTJ8jjnxGQIikPRToL2ZEXAMPLE=='}   

## action: 'delete target'
Delete the assessment target

Type: **generic**  
Read only: **False**

Deleting an assessment target will also delete corresponding templates, runs, and findings.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**target_arn** |  required  | ARN of the assessment target | string |  `aws inspector target arn`  `aws arn` 
**credentials** |  optional  | Assumed role credentials | string |  `aws credentials` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.target_arn | string |  `aws inspector target arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-KstwgEAp 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Target is deleted successfully 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.credentials | string |  `aws credentials`  |   {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Expiration': '2021-06-07 22:28:04', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SessionToken': 'EXAMPLEKEYTEST///////////wEaDFRU0s4AVrw0k0oYICK4ATAzOqzAkg9bHY29lYmP59UvVOHjLufOy4s7SnAzOxGqGIXnukLis4TWNhrJl5R5nYyimrm6K/9d0Cw2SWEXAMPLEEJHWJ+yY5Qk2QpWctS2BGn4n+G8cD6zEweCCMj+ScI5p8n7YI4wOdvXvOsVMmjV6F09Ujqr1w+NwoKXlglznXGs/7Q1kNZOMiioEhGUyoiHbQb37GCKslDK+oqe0KNaUKQ96YCepaLgMbMquDgdAM8I0TTxUO0o5ILF/gUyLT04R7QlOfktkdh6Qt0atTSEXAMPLEKEYTESTJ8jjnxGQIikPRToL2ZEXAMPLE=='}   

## action: 'list templates'
List the assessment templates of assessment targets

Type: **investigate**  
Read only: **True**

In the parameter <b>template_name</b>, the user can specify an explicit value or a string that contains a wildcard to match the value of the assessment template name.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**target_arns** |  optional  | List of target ARNs | string |  `aws inspector target arn`  `aws arn` 
**template_name** |  optional  | Assessment template name pattern | string | 
**limit** |  optional  | Maximum number of templates to be fetched | numeric | 
**credentials** |  optional  | Assumed role credentials | string |  `aws credentials` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   10 
action_result.parameter.target_arns | string |  `aws inspector target arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-6oqI2Cov 
action_result.parameter.template_name | string |  |   Assessment-Template-Default 
action_result.data.\*.arn | string |  |   arn:aws:inspector:us-east-1:849257271967:target/0-6oqI2Cov/template/0-26yzApF2 
action_result.data.\*.assessmentRunCount | numeric |  |   0 
action_result.data.\*.assessmentTargetArn | string |  `aws inspector target arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-6oqI2Cov 
action_result.data.\*.createdAt | string |  |   2019-05-16 17:50:28.198000+00:00 
action_result.data.\*.durationInSeconds | numeric |  |   3600 
action_result.data.\*.name | string |  |   Assessment-Template-Default 
action_result.data.\*.rulesPackageArns | string |  |   arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q 
action_result.summary.total_templates | numeric |  |   2 
action_result.message | string |  |   Total templates: 2 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.credentials | string |  `aws credentials`  |   {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Expiration': '2021-06-07 22:28:04', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SessionToken': 'EXAMPLEKEYTEST///////////wEaDFRU0s4AVrw0k0oYICK4ATAzOqzAkg9bHY29lYmP59UvVOHjLufOy4s7SnAzOxGqGIXnukLis4TWNhrJl5R5nYyimrm6K/9d0Cw2SWEXAMPLEEJHWJ+yY5Qk2QpWctS2BGn4n+G8cD6zEweCCMj+ScI5p8n7YI4wOdvXvOsVMmjV6F09Ujqr1w+NwoKXlglznXGs/7Q1kNZOMiioEhGUyoiHbQb37GCKslDK+oqe0KNaUKQ96YCepaLgMbMquDgdAM8I0TTxUO0o5ILF/gUyLT04R7QlOfktkdh6Qt0atTSEXAMPLEKEYTESTJ8jjnxGQIikPRToL2ZEXAMPLE=='}   

## action: 'list targets'
List the assessment target ARNs within the AWS account

Type: **investigate**  
Read only: **True**

In the parameter target_name, the user can specify an explicit value or a string that contains a wildcard to match the value of the assessment target name.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**target_name** |  optional  | Assessment target name pattern | string |  `aws inspector target name` 
**limit** |  optional  | Maximum number of targets to be fetched | numeric | 
**credentials** |  optional  | Assumed role credentials | string |  `aws credentials` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.limit | numeric |  |   10 
action_result.parameter.target_name | string |  `aws inspector target name`  |   test_target 
action_result.data.\*.createdAt | string |  |   2019-05-16 17:50:28.005000+00:00 
action_result.data.\*.name | string |  `aws inspector target name`  |   Assessment-Target-All-Instances 
action_result.data.\*.arn | string |  `aws inspector target arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-6oqI2Cov 
action_result.data.\*.updatedAt | string |  |   2019-05-16 17:50:28.005000+00:00 
action_result.summary.total_targets | numeric |  |   2 
action_result.message | string |  |   Total targets: 1  Total targets: 2 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.credentials | string |  `aws credentials`  |   {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Expiration': '2021-06-07 22:28:04', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SessionToken': 'EXAMPLEKEYTEST///////////wEaDFRU0s4AVrw0k0oYICK4ATAzOqzAkg9bHY29lYmP59UvVOHjLufOy4s7SnAzOxGqGIXnukLis4TWNhrJl5R5nYyimrm6K/9d0Cw2SWEXAMPLEEJHWJ+yY5Qk2QpWctS2BGn4n+G8cD6zEweCCMj+ScI5p8n7YI4wOdvXvOsVMmjV6F09Ujqr1w+NwoKXlglznXGs/7Q1kNZOMiioEhGUyoiHbQb37GCKslDK+oqe0KNaUKQ96YCepaLgMbMquDgdAM8I0TTxUO0o5ILF/gUyLT04R7QlOfktkdh6Qt0atTSEXAMPLEKEYTESTJ8jjnxGQIikPRToL2ZEXAMPLE=='}   

## action: 'run assessment'
Start the assessment run specified by the assessment template ARN

Type: **generic**  
Read only: **False**

While an assessment run is in the COLLECTING_DATA state then, all other assessment runs will fail.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**template_arn** |  required  | Assessment template ARN to start the assessment run of | string |  `aws inspector template arn`  `aws arn` 
**assessment_run_name** |  optional  | Name of the assessment run | string | 
**credentials** |  optional  | Assumed role credentials | string |  `aws credentials` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.assessment_run_name | string |  |   test-template/2019-05-29T06:35/Uom2 
action_result.parameter.template_arn | string |  `aws inspector template arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-QRxUrrdI 
action_result.data.\*.arn | string |  `aws inspector assessment run arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-QRxUrrdI/run/0-D2egFbHs 
action_result.data.\*.assessmentTemplateArn | string |  `aws inspector template arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-QRxUrrdI 
action_result.data.\*.createdAt | string |  |   2019-05-29 09:47:05.864000+00:00 
action_result.data.\*.dataCollected | boolean |  |   True  False 
action_result.data.\*.durationInSeconds | numeric |  |   3600 
action_result.data.\*.name | string |  |   test-template/2019-05-29T09:47/RmfI 
action_result.data.\*.rulesPackageArns | string |  |   arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q 
action_result.data.\*.startedAt | string |  |   2019-05-29 09:47:06.687000+00:00 
action_result.data.\*.state | string |  |   COLLECTING_DATA 
action_result.data.\*.stateChangedAt | string |  |   2019-05-29 09:47:06.687000+00:00 
action_result.data.\*.stateChanges.\*.state | string |  |   CREATED 
action_result.data.\*.stateChanges.\*.stateChangedAt | string |  |   2019-05-29 09:47:05.863000+00:00 
action_result.summary.assessment_run_arn | numeric |  `aws inspector assessment run arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-QRxUrrdI/run/0-D2egFbHs 
action_result.message | string |  |   Assessment run arn: arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-QRxUrrdI/run/0-D2egFbHs 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.credentials | string |  `aws credentials`  |   {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Expiration': '2021-06-07 22:28:04', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SessionToken': 'EXAMPLEKEYTEST///////////wEaDFRU0s4AVrw0k0oYICK4ATAzOqzAkg9bHY29lYmP59UvVOHjLufOy4s7SnAzOxGqGIXnukLis4TWNhrJl5R5nYyimrm6K/9d0Cw2SWEXAMPLEEJHWJ+yY5Qk2QpWctS2BGn4n+G8cD6zEweCCMj+ScI5p8n7YI4wOdvXvOsVMmjV6F09Ujqr1w+NwoKXlglznXGs/7Q1kNZOMiioEhGUyoiHbQb37GCKslDK+oqe0KNaUKQ96YCepaLgMbMquDgdAM8I0TTxUO0o5ILF/gUyLT04R7QlOfktkdh6Qt0atTSEXAMPLEKEYTESTJ8jjnxGQIikPRToL2ZEXAMPLE=='}   

## action: 'get findings'
List and describe the findings generated by the assessment runs

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**assessment_run_arns** |  optional  | List of the assessment runs ARNs (Max Limit: 50) | string |  `aws inspector assessment run arn`  `aws arn` 
**severities** |  optional  | List of severity values (case-sensitive) (Max Limit: 50) | string | 
**limit** |  optional  | Maximum number of findings to be fetched | numeric | 
**credentials** |  optional  | Assumed role credentials | string |  `aws credentials` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.assessment_run_arns | string |  `aws inspector assessment run arn`  `aws arn`  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-weJjg0hC/run/0-ZjmO3RKu 
action_result.parameter.limit | numeric |  |   5 
action_result.parameter.severities | string |  |   High  Low  Medium  Undefined  Informational 
action_result.data.\*.arn | string |  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-weJjg0hC/run/0-ZjmO3RKu/finding/0-cOjmYFiJ 
action_result.data.\*.assetAttributes.agentId | string |  `aws ec2 instance id`  |   i-0edb2f67d116434a5 
action_result.data.\*.assetAttributes.amiId | string |  |   ami-07b8352fea5b7a594 
action_result.data.\*.assetAttributes.hostname | string |  `host name`  |   ec2-23-20-100-84.compute-1.amazonaws.com 
action_result.data.\*.assetAttributes.networkInterfaces.\*.networkInterfaceId | string |  |   eni-03bfd52b58267d6e4 
action_result.data.\*.assetAttributes.networkInterfaces.\*.privateDnsName | string |  |   ip-172-31-45-141.ec2.internal 
action_result.data.\*.assetAttributes.networkInterfaces.\*.privateIpAddress | string |  `ip`  |   172.31.45.141 
action_result.data.\*.assetAttributes.networkInterfaces.\*.privateIpAddresses.\*.privateDnsName | string |  |   ip-172-31-45-141.ec2.internal 
action_result.data.\*.assetAttributes.networkInterfaces.\*.privateIpAddresses.\*.privateIpAddress | string |  `ip`  |   172.31.45.141 
action_result.data.\*.assetAttributes.networkInterfaces.\*.publicDnsName | string |  |   ec2-23-20-100-84.compute-1.amazonaws.com 
action_result.data.\*.assetAttributes.networkInterfaces.\*.publicIp | string |  `ip`  |   23.20.100.84 
action_result.data.\*.assetAttributes.networkInterfaces.\*.securityGroups.\*.groupId | string |  |   sg-00c60fd41aea33c09 
action_result.data.\*.assetAttributes.networkInterfaces.\*.securityGroups.\*.groupName | string |  |   nginx-default-sg 
action_result.data.\*.assetAttributes.networkInterfaces.\*.subnetId | string |  |   subnet-97f8b0ca 
action_result.data.\*.assetAttributes.networkInterfaces.\*.vpcId | string |  `aws ec2 vpc id`  |   vpc-5113dc2a 
action_result.data.\*.assetAttributes.schemaVersion | numeric |  |   1 
action_result.data.\*.assetAttributes.tags.\*.key | string |  |   InstanceOwnerEmail  Name 
action_result.data.\*.assetAttributes.tags.\*.value | string |  `email`  |   test 
action_result.data.\*.assetType | string |  |   ec2-instance 
action_result.data.\*.attributes.\*.key | string |  |   ENI 
action_result.data.\*.attributes.\*.value | string |  |   eni-084422612470a9c63 
action_result.data.\*.confidence | numeric |  |   10 
action_result.data.\*.createdAt | string |  |   2019-05-29 14:09:34.077000+00:00 
action_result.data.\*.description | string |  |   On this instance, TCP port 23, which is associated with Telnet, is reachable from the internet. You can install the Inspector agent on this instance and re-run the assessment to check for any process listening on this port. The instance i-0edb2f67d116434a5 is located in VPC vpc-5113dc2a and has an attached ENI eni-03bfd52b58267d6e4 which uses network ACL acl-018ed07a. The port is reachable from the internet through Security Group sg-00c60fd41aea33c09 and IGW igw-0b758073 
action_result.data.\*.id | string |  |   Recognized port reachable from internet 
action_result.data.\*.indicatorOfCompromise | boolean |  |   True  False 
action_result.data.\*.numericSeverity | numeric |  |   9 
action_result.data.\*.recommendation | string |  |   You can edit the Security Group sg-00c60fd41aea33c09 to remove access from the internet on port 23 
action_result.data.\*.schemaVersion | numeric |  |   1 
action_result.data.\*.service | string |  |   Inspector 
action_result.data.\*.serviceAttributes.assessmentRunArn | string |  |   arn:aws:inspector:us-east-1:849257271967:target/0-evshZX5K/template/0-weJjg0hC/run/0-ZjmO3RKu 
action_result.data.\*.serviceAttributes.rulesPackageArn | string |  |   arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd 
action_result.data.\*.serviceAttributes.schemaVersion | numeric |  |   1 
action_result.data.\*.severity | string |  |   High  Low  Medium  Undefined  Informational 
action_result.data.\*.title | string |  |   On instance i-0edb2f67d116434a5, TCP port 23 which is associated with 'Telnet' is reachable from the internet 
action_result.data.\*.updatedAt | string |  |   2019-05-29 14:09:34.077000+00:00 
action_result.summary.total_findings | numeric |  |   5 
action_result.summary.total_templates | numeric |  |   233 
action_result.message | string |  |   Total findings: 5 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.parameter.credentials | string |  `aws credentials`  |   {'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE', 'Expiration': '2021-06-07 22:28:04', 'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'SessionToken': 'EXAMPLEKEYTEST///////////wEaDFRU0s4AVrw0k0oYICK4ATAzOqzAkg9bHY29lYmP59UvVOHjLufOy4s7SnAzOxGqGIXnukLis4TWNhrJl5R5nYyimrm6K/9d0Cw2SWEXAMPLEEJHWJ+yY5Qk2QpWctS2BGn4n+G8cD6zEweCCMj+ScI5p8n7YI4wOdvXvOsVMmjV6F09Ujqr1w+NwoKXlglznXGs/7Q1kNZOMiioEhGUyoiHbQb37GCKslDK+oqe0KNaUKQ96YCepaLgMbMquDgdAM8I0TTxUO0o5ILF/gUyLT04R7QlOfktkdh6Qt0atTSEXAMPLEKEYTESTJ8jjnxGQIikPRToL2ZEXAMPLE=='} 