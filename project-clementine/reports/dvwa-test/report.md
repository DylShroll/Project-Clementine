# Project Clementine — Security Assessment Report

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 17 |
| MEDIUM | 32 |
| LOW | 17 |
| INFO | 0 |

**Attack Chains Identified:** 0

## Findings

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-northeast-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-northeast-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-northeast-3:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-south-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-southeast-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ap-southeast-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:ca-central-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-central-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-north-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-west-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-west-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:eu-west-3:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:sa-east-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-east-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-east-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-west-1:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [HIGH] Region has at least one CloudTrail trail logging
- **Category:** cloudtrail_multi_region_enabled
- **Resource:** arn:aws:cloudtrail:us-west-2:760689105616:trail

**AWS CloudTrail** has at least one trail with `logging` enabled in every region. A **multi-region trail** or a regional trail counts for coverage in that region.

**Remediation:** Use a **multi-region CloudTrail trail** or per-region trails so `logging` is active in every region, including unused ones.

Centralize logs, enforce **least privilege** to log stores, and add **defense-in-depth** with encryption, integrity validation, and retention. Continuously monitor trail health to catch gaps.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-northeast-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-northeast-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-northeast-3:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-south-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-southeast-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ap-southeast-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:ca-central-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-central-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-north-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-west-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-west-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:eu-west-3:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:sa-east-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-east-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-east-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-west-1:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [LOW] IAM Access Analyzer is enabled
- **Category:** accessanalyzer_enabled
- **Resource:** arn:aws:accessanalyzer:us-west-2:760689105616:analyzer/unknown

**IAM Access Analyzer** presence and status are evaluated per account and Region. An analyzer in `ACTIVE` state indicates continuous analysis of supported resources and IAM activity to identify external, internal, and unused access.

**Remediation:** Enable **IAM Access Analyzer** across all accounts and active Regions (*or organization-wide*). Operate on least privilege: continuously review findings, remove unintended access, and trim unused permissions. Use archive rules sparingly, integrate reviews into change/CI/CD workflows, and enforce separation of duties on policy changes.

### [MEDIUM] CloudWatch log metric filter and alarm exist for Network ACL (NACL) change events
- **Category:** cloudwatch_changes_to_network_acls_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudTrail records for **Network ACL changes** are matched by a CloudWatch Logs metric filter with an associated alarm for events like `CreateNetworkAcl`, `CreateNetworkAclEntry`, `DeleteNetworkAcl`, `DeleteNetworkAclEntry`, `ReplaceNetworkAclEntry`, and `ReplaceNetworkAclAssociation`.

**Remediation:** Implement a CloudWatch Logs metric filter and alarm for NACL change events from CloudTrail and route alerts to responders. Enforce **least privilege** on NACL management, require **change control**, and use **defense in depth** with configuration monitoring and flow logs to validate and monitor network posture.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for changes to network gateways
- **Category:** cloudwatch_changes_to_network_gateways_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudWatch log metric filters and alarms for **network gateway changes** are identified by matching CloudTrail events such as `CreateCustomerGateway`, `DeleteCustomerGateway`, `AttachInternetGateway`, `CreateInternetGateway`, `DeleteInternetGateway`, and `DetachInternetGateway` in log groups that receive trail logs.

**Remediation:** Send CloudTrail to CloudWatch Logs and create a metric filter for the listed gateway events with an alarm that notifies responders. Enforce **least privilege** for gateway modifications, require change approvals, and route alerts to monitored channels as part of **defense in depth**.

### [MEDIUM] Account monitors VPC route table changes with a CloudWatch Logs metric filter and alarm
- **Category:** cloudwatch_changes_to_network_route_tables_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**VPC route table changes** are captured from **CloudTrail logs** by a **CloudWatch Logs metric filter** with an associated **alarm** for events like `CreateRoute`, `CreateRouteTable`, `ReplaceRoute`, `ReplaceRouteTableAssociation`, `DeleteRoute`, `DeleteRouteTable`, and `DisassociateRouteTable`.

**Remediation:** Implement a **CloudWatch Logs metric filter and alarm** on CloudTrail for these route table events and notify responders. Enforce **least privilege** for route modifications, require **change control**, and apply **defense in depth** with VPC Flow Logs and guardrails to prevent and quickly contain unsafe routing changes.

### [MEDIUM] AWS account has a CloudWatch Logs metric filter and alarm for VPC changes
- **Category:** cloudwatch_changes_to_vpcs_alarm_configured
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail events** for **VPC configuration changes** are captured in CloudWatch Logs with a metric filter and an associated alarm. The filter targets actions like `CreateVpc`, `DeleteVpc`, `ModifyVpcAttribute`, and VPC peering operations to surface when network topology is altered.

**Remediation:** Create a CloudWatch Logs metric filter and alarm on CloudTrail for critical **VPC change events**, and notify responders. Apply **least privilege** to network changes, require change approvals, and use **defense in depth** (segmentation, route controls) to prevent and contain unauthorized modifications.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for AWS Config configuration changes
- **Category:** cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudTrail logs in **CloudWatch Logs** are inspected for a metric filter and alarm that track **AWS Config configuration changes**, specifically `StopConfigurationRecorder`, `DeleteDeliveryChannel`, `PutDeliveryChannel`, and `PutConfigurationRecorder` events from `config.amazonaws.com`.

**Remediation:** Create a **CloudWatch Logs metric filter and alarm** for `config.amazonaws.com` events (`StopConfigurationRecorder`, `DeleteDeliveryChannel`, `PutDeliveryChannel`, `PutConfigurationRecorder`). Route CloudTrail to Logs, notify responders, and enforce **least privilege** and **separation of duties** on Config changes to prevent abuse.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for CloudTrail configuration changes
- **Category:** cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail logs** include a **metric filter** for trail configuration events (`CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, `StopLogging`) with an associated **CloudWatch alarm** to alert on matches.

Evaluates the presence of this filter-and-alarm monitoring.

**Remediation:** Implement a **metric filter** for trail configuration events and a linked **alarm** that notifies response channels.

Apply **least privilege** and **separation of duties** for trail changes, add **defense in depth** with centralized logging and validation, and regularly test that alerts fire.

### [MEDIUM] Account has a CloudWatch Logs metric filter and alarm for AWS Management Console authentication failures
- **Category:** cloudwatch_log_metric_filter_authentication_failures
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudWatch Logs metric filter and alarm for **AWS Management Console authentication failures**, sourced from CloudTrail (`eventName=ConsoleLogin`, `errorMessage="Failed authentication"`).

Identifies whether these failures are converted into a metric and actively monitored by an alarm.

**Remediation:** Implement a log metric filter for `ConsoleLogin` failures and attach a **CloudWatch alarm** with actionable notifications. Tune thresholds to reduce noise and route alerts to incident response.

Apply **least privilege** and enforce **MFA** to limit impact, and correlate alerts with source IP and user context.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for AWS Organizations changes
- **Category:** cloudwatch_log_metric_filter_aws_organizations_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudWatch Logs** metric filters and alarms monitor **AWS Organizations** change events recorded by CloudTrail, including actions like `CreateAccount`, `AttachPolicy`, `MoveAccount`, and `UpdateOrganizationalUnit`.

The evaluation looks for a filter on the trail log group matching `organizations.amazonaws.com` events and an alarm linked to that metric.

**Remediation:** Send CloudTrail events to **CloudWatch Logs**, add a metric filter for `organizations.amazonaws.com` change events, and attach an alarm that notifies responders. Enforce **least privilege** and **separation of duties** for org admins, require MFA and approvals, and regularly test alerts to ensure timely detection and response.

### [MEDIUM] Account has a CloudWatch log metric filter and alarm for disabling or scheduled deletion of customer-managed KMS keys
- **Category:** cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudTrail events delivered to CloudWatch are evaluated for a **metric filter and alarm** that monitor **KMS CMK state changes**, specifically `DisableKey` and `ScheduleKeyDeletion` from `kms.amazonaws.com`.

**Remediation:** Establish **CloudWatch metric filters and alarms** for `DisableKey` and `ScheduleKeyDeletion` CloudTrail events to enable rapid response.
- Apply **least privilege** to KMS administration
- Enforce **change control** and separation of duties
- Use deletion waiting periods and monitor all regions

### [MEDIUM] CloudWatch log metric filter and alarm exist for S3 bucket policy changes
- **Category:** cloudwatch_log_metric_filter_for_s3_bucket_policy_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail** logs are assessed for a **CloudWatch metric filter** matching S3 bucket configuration changes (ACL, policy, CORS, lifecycle, replication; e.g., `PutBucketPolicy`, `DeleteBucketPolicy`) and for an associated **CloudWatch alarm**.

**Remediation:** Establish and maintain **metric filters** and **alarms** for S3 bucket policy, ACL, CORS, lifecycle, and replication changes. Route alerts to monitored channels and integrate with SIEM. Enforce **least privilege**, require change reviews, and use **defense in depth** to prevent and quickly detect unsafe bucket policy changes.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for IAM policy changes
- **Category:** cloudwatch_log_metric_filter_policy_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

CloudWatch uses a metric filter and alarm to track **IAM policy changes** recorded by CloudTrail (e.g., `CreatePolicy`, `DeletePolicy`, version changes, inline policy edits, policy attach/detach). This finding reflects whether that filter and an associated alarm are present on the trail's log group.

**Remediation:** Create a metric filter for IAM policy create/update/delete and attach/detach events with an **alarm** to notify responders.
- Enforce **least privilege** and separation of duties for policy changes
- Require approvals and central logging across Regions/accounts
- Integrate alerts with incident response

### [MEDIUM] Account has a CloudWatch Logs metric filter and alarm for root account usage
- **Category:** cloudwatch_log_metric_filter_root_usage
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail** logs in CloudWatch include a metric filter for **root account activity** (`{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`) and a linked CloudWatch alarm that triggers when the filter matches.

**Remediation:** Enable real-time alerts for **root activity** using a log metric filter and a high-priority alarm with notifications.

Reduce exposure: enforce **least privilege**, keep root for *break-glass* with MFA, disable root access keys, and route alerts into incident response for **defense in depth**.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for security group changes
- **Category:** cloudwatch_log_metric_filter_security_group_changes
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail** events for **security group configuration changes** are monitored using a **CloudWatch Logs metric filter** with an associated **alarm**. The filter targets actions like `AuthorizeSecurityGroupIngress/Egress`, `RevokeSecurityGroupIngress/Egress`, `CreateSecurityGroup`, and `DeleteSecurityGroup` to surface any security group modifications.

**Remediation:** Establish real-time alerts for **security group modifications** by sending CloudTrail to CloudWatch, creating metric filters and alarms, and notifying responders.
- Enforce **least privilege** on SG changes
- Use change management and tagging
- Centralize logs, test alarms, and maintain runbooks
- Layer with NACLs and WAF for **defense in depth**

### [MEDIUM] CloudWatch log metric filter and alarm exist for Management Console sign-in without MFA
- **Category:** cloudwatch_log_metric_filter_sign_in_without_mfa
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudTrail logs** in CloudWatch are assessed for a metric filter and alarm that detect console logins where `$.eventName = ConsoleLogin` and `$.additionalEventData.MFAUsed != \"Yes\"`.

This reflects whether alerting exists for sign-ins that occur without **MFA**.

**Remediation:** Enforce **MFA** for all console-capable identities and maintain alerts for `ConsoleLogin` with `MFAUsed != \"Yes\"`.

Apply **least privilege**, route alarms to monitored channels, and tune for SSO to reduce noise. Test alarms regularly and review coverage as part of **defense in depth**.

### [MEDIUM] CloudWatch Logs metric filter and alarm exist for unauthorized API calls
- **Category:** cloudwatch_log_metric_filter_unauthorized_api_calls
- **Resource:** arn:aws:logs:us-east-2:760689105616:log-group

**CloudWatch Logs** for CloudTrail include a metric filter that matches unauthorized API errors (`$.errorCode="*UnauthorizedOperation"` or `$.errorCode="AccessDenied*"`) and a linked alarm that triggers when events match the filter.

**Remediation:** Enable real-time **alerting** by adding a CloudWatch Logs metric filter for unauthorized errors (`*UnauthorizedOperation`, `AccessDenied*`) and associating it with an alarm that notifies responders.
- Enforce **least privilege** to reduce noise
- Integrate with IR tooling for **defense in depth**

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-northeast-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-northeast-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-northeast-3:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-south-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-southeast-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ap-southeast-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:ca-central-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-central-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-north-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-west-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-west-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:eu-west-3:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:sa-east-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-east-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-east-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-west-1:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.

### [MEDIUM] AWS Config recorder is enabled and not in failure state or disabled
- **Category:** config_recorder_all_regions_enabled
- **Resource:** arn:aws:config:us-west-2:760689105616:recorder

**AWS accounts** have **AWS Config recorders** active and healthy in each Region. It identifies Regions with no recorder, a disabled recorder, or a recorder in a failure state.

**Remediation:** Enable **AWS Config** in every Region with continuous recording and maintain healthy recorder status.
