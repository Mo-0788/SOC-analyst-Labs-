Detecting VM Deletions in Azure with KQL (Microsoft Sentinel Lab)
Overview
This lab demonstrates how to detect Azure Virtual Machine deletion events using Kusto Query Language (KQL) in Microsoft Sentinel / Log Analytics. Deleting a VM is a high-impact action that attackers or malicious insiders may use to destroy evidence, disrupt services, or cause data loss. Monitoring for this activity is a common SOC detection use case tied to insider threat and incident response scenarios.

Objective
Build and run a KQL query against the AzureActivity table to identify successful VM deletion events in the last 24 hours, capturing who performed the action, from what IP address, and which resource was affected.

Environment
Platform: Microsoft Azure
Tooling: Microsoft Sentinel / Log Analytics Workspace
Data source: AzureActivity table
Query language: KQL (Kusto Query Language)
