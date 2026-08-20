Detecting VM Deletions in Azure with KQL (Microsoft Sentinel Lab)
Overview
in This lab  I worked on  how to detect Azure Virtual Machine deletion events using Kusto Query Language (KQL) in Microsoft Sentinel / Log Analytics.
Deleting a VM is a high-impact action that attackers or malicious insiders may use to destroy evidence, disrupt services, or cause data loss. Monitoring for this activity is a common SOC detection use case tied to insider threat and incident response scenarios. this can help if you have a number of VM and you want to monitor the logs activity (student or clients) and want to know who delete and what VM? and if it success or failed. 

Objective
Build and run a KQL query against the AzureActivity table to identify successful VM deletion events in the last 360 days, capturing who performed the action, from what IP address, and which resource was affected.

1. Environment
Platform: Microsoft Azure
Tooling: Microsoft Sentinel / Log Analytics Workspace
Data source: AzureActivity table
Query language: KQL (Kusto Query Language)

2. Kusto Query   
enter the work environment which is Microsoft Defender/Advanced hunting in the Azure portal. 
enter the the following K Query. 
AzureActivity
| where TimeGenerated > ago(360d)
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/delete"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup, _ResourceId, CallerIpAddress
| sort by TimeGenerated desc 

you can enter each line of the query and click run so you will see the result of that specific command as example you can run at the first"
{AzureActivity
| where TimeGenerated > ago(360d) 
the result shows all the Azure activity for the last year, you will see how we narrowed the result to final activity we are looking for. 
se the screenshot of the first part of the query 
<img width="1267" height="704" alt="azure activity overview " src="https://github.com/user-attachments/assets/296d6153-62b6-4eb3-a102-c09adaa28f9b" />


3. Query breakdown: 

| where TimeGenerated > ago(24h)	Limits results to the last 360 days. 
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/delete"	Filters for the specific Azure Resource Manager operation that deletes a VM (=~ makes the match case-insensitive)
| where ActivityStatusValue == "Success"	Ensures only completed (successful) deletions are shown, not failed/attempted ones. if you want the failed just replace "Success" with "Failure"
| project ...	Selects only the relevant fields for the investigation
| sort by TimeGenerated desc	Orders results with the most recent deletion first 

4. Run the query and review results
Executed the query and reviewed the output, which returned the following fields:

TimeGenerated — timestamp of the deletion event
Caller — the user or service principal that performed the deletion
CallerIpAddress — the source IP address of the request
OperationNameValue — confirms the operation type (VM delete)
ResourceGroup — the resource group containing the deleted VM
_ResourceId — the full resource ID of the deleted VM
<img width="1275" height="707" alt="the final result of the query " src="https://github.com/user-attachments/assets/c6d26290-ddca-41ce-96c6-8e71a543e156" />
note: for security reason I hide the Ip address

5 Validate findings

the last screenshot Confirmed the query correctly captured the test VM deletion, matching the expected Caller, timestamp, and resource group from for the last 360 days.

Analysis

This query provides the core "who, what, when, where" of a VM deletion event:

Who: Caller and CallerIpAddress identify the actor and their origin.
What: OperationNameValue confirms the exact action taken.
When: TimeGenerated timestamps the event.
Where: ResourceGroup and _ResourceId pinpoint the affected asset.

In SOC environment, this query could be converted into a Sentinel Analytics Rule to automatically generate an alert/incident whenever a VM deletion occurs, especially if performed outside business hours, by an unexpected user, or from an unfamiliar IP address.
