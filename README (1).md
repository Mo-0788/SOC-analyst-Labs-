# Microsoft Defender for Endpoint: KQL Query Reference

Queries I used in the [MDE investigation package lab](../mde-investigation-package-analysis/README.md), for quick reference. Run them in **Defender portal → Hunting → Advanced hunting**.

> [!NOTE]
> The device name is partly hidden. `abd` is the start of my VM name. Replace it with the start of your own device name.

## Before you run anything
- Set the **time range** (top right) first. Use 24 hours or 7 days.
- Defender only has data **after the device is onboarded**. Older activity returns 0 results.
- Use `startswith` for `DeviceName`. The full name often has a domain after it, so `==` can miss it.
- `project` keeps only the columns you list. Remove it to see all columns, including hashes.
- Run one query at a time. Select it, then click **Run query**.

## Query index

| # | Goal | Table | Status |
|---|------|-------|--------|
| 1 | [Check onboarding and sensor health](#1-check-onboarding-and-sensor-health) | `DeviceInfo` | Used. Showed "Can be onboarded" before onboarding. |
| 2 | [Is any device sending process data?](#2-is-any-device-sending-process-data) | `DeviceProcessEvents` | Used. 0 rows before onboarding. |
| 3 | [Latest processes on my device](#3-latest-processes-on-my-device) | `DeviceProcessEvents` | Used. 50 rows after onboarding. |
| 4 | [Find Tor Browser processes](#4-find-tor-browser-processes) | `DeviceProcessEvents` | Used. 0 rows: Tor ran before onboarding. |
| 5 | [Find Tor Browser files](#5-find-tor-browser-files) | `DeviceFileEvents` | Used. 0 rows: same reason. |
| 6 | [Search command lines](#6-search-command-lines) | `DeviceProcessEvents` | Used |
| 7 | [Were my test files opened?](#7-were-my-test-files-opened) | `DeviceProcessEvents` | Used. 0 rows: wrong table and files opened before onboarding. |
| 8 | [Track my test files](#8-track-my-test-files) | `DeviceFileEvents` | Used |
| 9 | [Failed logons by source](#9-failed-logons-by-source) | `DeviceLogonEvents` | Used |
| 10 | [Alerts on my device](#10-alerts-on-my-device) | `AlertInfo`, `AlertEvidence` | Used. 22 alerts. |
| 11 | [Templates from the course table](#11-templates-from-the-course-table) | Network, Registry, Events | Template |

---

## 1. Check onboarding and sensor health
```kusto
DeviceInfo
| where DeviceName startswith "abd"
| project Timestamp, DeviceName, OnboardingStatus, SensorHealthState, OSPlatform
| sort by Timestamp desc
```
`OnboardingStatus` must say **Onboarded**. "Can be onboarded" means Defender only discovered the device.

## 2. Is any device sending process data?
```kusto
DeviceProcessEvents
| take 10
```
Empty result: no device in the tenant is sending process data. Other device names: the problem is only my device.

## 3. Latest processes on my device
```kusto
let MyDevice = "abd";
DeviceProcessEvents
| where DeviceName startswith MyDevice
| sort by Timestamp desc
| take 100
```

## 4. Find Tor Browser processes
```kusto
let MyDevice = "abd";
DeviceProcessEvents
| where DeviceName startswith MyDevice
| where FileName in~ ("firefox.exe", "tor.exe") or FileName startswith "tor-browser"
| project Timestamp, FileName, FolderPath, ProcessCommandLine, AccountName
| sort by Timestamp desc
```
Tor Browser runs as `firefox.exe` and `tor.exe`.

## 5. Find Tor Browser files
```kusto
let MyDevice = "abd";
DeviceFileEvents
| where DeviceName startswith MyDevice
| where FileName has_any ("tor-browser", "tor.exe")
| project Timestamp, ActionType, FileName, FolderPath
| sort by Timestamp desc
```

## 6. Search command lines
```kusto
let MyDevice = "abd";
DeviceProcessEvents
| where DeviceName startswith MyDevice
| where ProcessCommandLine has_any ("tor", "powershell")
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```

## 7. Were my test files opened?
```kusto
let MyDevice = "abd";
DeviceProcessEvents
| where DeviceName startswith MyDevice
| where ProcessCommandLine has "corporate_earnings" or ProcessCommandLine has "corporate_report"
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp desc
```
`DeviceProcessEvents` records programs that start, not files that open. The file name only appears in the command line of the program (for example `notepad.exe`).

## 8. Track my test files
```kusto
let MyDevice = "abd";
DeviceFileEvents
| where DeviceName startswith MyDevice
| where FileName has "corporate_"
| sort by Timestamp desc
```
Shows when files were created, renamed or changed. Includes `SHA1`, `SHA256`, `MD5` and the process that touched the file.

## 9. Failed logons by source
```kusto
DeviceLogonEvents
| where DeviceName startswith "abd"
| where ActionType == "LogonFailed"
| summarize Attempts = count() by RemoteIP, AccountName
| sort by Attempts desc
```
Used to look for password guessing. In the package, the Security log (Event ID 4625) showed 7,205 failed network logons.

## 10. Alerts on my device
```kusto
AlertInfo
| join kind=inner (
    AlertEvidence
    | where DeviceName startswith "abd"
    | distinct AlertId
  ) on AlertId
| project Timestamp, Title, Severity, Category
| sort by Timestamp desc
```
Lists every alert linked to the device. Export the result with **Export → CSV**.

## 11. Templates from the course table
Not all of these were run in my lab. Use them to test each table with the action in the first column.

| Lab action | Table | Key `ActionType` |
|---|---|---|
| Sign in or RDP to the VM | `DeviceLogonEvents` | `LogonSuccess` |
| Run `cmd /c whoami` | `DeviceProcessEvents` | `ProcessCreated` |
| `Invoke-WebRequest` to a website | `DeviceNetworkEvents` | `ConnectionSuccess` |
| Write a file to `\Temp\` | `DeviceFileEvents` | `FileCreated` |
| `reg add` a Run key value | `DeviceRegistryEvents` | `RegistryValueSet` |
| `schtasks /create` a task | `DeviceEvents` | `ScheduledTaskCreated` |

```kusto
let MyDevice = "abd";
DeviceProcessEvents
| where DeviceName startswith MyDevice
| where ProcessCommandLine has "whoami"
| sort by Timestamp desc
```

```kusto
let MyDevice = "abd";
DeviceNetworkEvents
| where DeviceName startswith MyDevice
| where ActionType == "ConnectionSuccess"
| project Timestamp, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| sort by Timestamp desc
```

```kusto
let MyDevice = "abd";
DeviceFileEvents
| where DeviceName startswith MyDevice
| where FolderPath has @"\Temp\" and ActionType == "FileCreated"
| sort by Timestamp desc
```

```kusto
let MyDevice = "abd";
DeviceRegistryEvents
| where DeviceName startswith MyDevice
| where ActionType == "RegistryValueSet" and RegistryKey has @"CurrentVersion\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by Timestamp desc
```

```kusto
let MyDevice = "abd";
DeviceEvents
| where DeviceName startswith MyDevice
| where ActionType == "ScheduledTaskCreated"
| sort by Timestamp desc
```

---

## Command-line checks on the VM (not KQL)

| Command | Use |
|---|---|
| `sc query sense` | Check the Defender sensor. `STATE: 4 RUNNING` is healthy. |
| `sc start sense` | Start the sensor. If it stops again, the device is not onboarded. |

## Common reasons for 0 results

| Cause | Fix |
|---|---|
| Device not onboarded, or activity happened before onboarding | Onboard first, then repeat the activity |
| Wrong table (for example, file name in `DeviceProcessEvents`) | Use `DeviceFileEvents` for files |
| `DeviceName ==` does not match the full name | Use `startswith` |
| Time range too short | Set 24 hours, 7 days or 30 days |
| Just did the activity | Wait 5 to 10 minutes |

---

*AI assistance (Claude) was used to help organize this reference. Queries were run and reviewed by me.*
