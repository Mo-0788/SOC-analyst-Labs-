
# MDE Investigation Package Lab: Finding Tor Browser Use and Internet Password Guessing on a Windows VM


## Table of Contents
1. [Summary](#1-summary)
2. [Lab setup](#2-lab-setup)
3. [Steps](#3-steps)
   - [3.1 Prepare the VM](#31-prepare-the-vm)
   - [3.2 Onboard the VM to Defender for Endpoint](#32-onboard-the-vm-to-defender-for-endpoint)
   - [3.3 Collect the investigation package](#33-collect-the-investigation-package)
   - [3.4 Quick check with KQL](#34-quick-check-with-kql-advanced-hunting)
4. [What was in the package](#4-what-was-in-the-package)
5. [Findings in detail](#5-findings-in-detail)
   - [Finding 1: Failed logons from the internet](#finding-1-many-failed-logons-from-the-internet-high)
   - [Finding 2: Tor Browser ran](#finding-2-tor-browser-ran-on-the-vm-medium)
   - [Finding 3: The live snapshot is clean](#finding-3-the-live-snapshot-is-clean-info)
   - [Finding 4: Onboarding changed the machine](#finding-4-defender-onboarding-changed-the-machine-info)
6. [Timeline](#6-timeline-utc)
7. [Limits of this investigation](#7-limits-of-this-investigation)
8. [Lessons learned](#8-lessons-learned)
9. [Tools used](#9-tools-used)

# Collecting and Analyzing an Investigation Package in Microsoft Defender for Endpoint

A hands-on lab write-up. I collected an **investigation package** from a Windows 11 test VM using Microsoft Defender for Endpoint (MDE), then read the files to see what happened on the machine.

> [!WARNING]
> **Lab only.** Everything here was done on a test VM in a training lab. Do not run these steps on a real work computer.

> [!NOTE]
> **Privacy note.** Sensitive details are partly hidden on purpose. Examples: host name `ab***-vm`, user `a****1`, IP addresses `59.18.x.x`. I do not publish the raw package.

---

## 1. Summary

| # | Finding | Importance |
|---|---------|-----------|
| 1 | **7,205 failed network logons** from **6 outside IP addresses** over about 8.5 hours. Most tried the user names `Administrator` and `admin`. | **High** |
| 2 | **No successful logon from any of those outside IPs.** All successful logons came from internal `10.0.8.x` addresses (consistent with Azure Bastion), using the one admin account. | Good news |
| 3 | **Tor Browser (portable)** was run from the Desktop on 10 Oct 2026. Defender's package shows it in Prefetch and in the Background Activity Moderator (BAM) registry data, **not** in Installed Programs. | Medium (expected in this lab) |
| 4 | The **live snapshot is clean**: no suspicious processes, no strange network connections, no extra accounts, no unknown scheduled tasks. | Info |
| 5 | The collection itself worked: **70 of 70 commands completed with no errors.** | Info |

**Most important finding:** the VM was being **password-guessed from the internet**. This is a real risk even in a lab. The logs show it did not succeed, but the VM should not be reachable this way.

---

## 2. Lab setup

- Windows 11 Pro virtual machine in Azure (connected through Azure Bastion)
- Microsoft Defender for Endpoint (MDE) in a training tenant
- Test activity on the VM:
  - A folder with two sample files: `corporate_report.txt` and `corporate_earnings.txt`
  - Tor Browser installed (a tool that often raises questions in a company network)

---

## 3. Steps

### 3.1 Prepare the VM
1. Create a folder on the desktop with the two sample files.
2. Download and run the portable **Tor Browser**, and open it once.

### 3.2 Onboard the VM to Defender for Endpoint
My VM first showed as **"Can be onboarded"** and all response actions were greyed out. A device must be **onboarded** before you can collect a package.

1. In the portal: **Settings → Endpoints → Onboarding**.
2. Choose **Windows 10 and 11**, **Local script**, connectivity type **Streamlined**.
3. Download the onboarding package. (The button was greyed out for my account because it had no admin role. The lab admins gave me the package.)

<img width="1272" height="677" alt="onboarding steps" src="https://github.com/user-attachments/assets/f8c7876d-438b-44e0-9361-c5a55ff6c4f8" />


4. On the VM, run `WindowsDefenderATPLocalOnboardingScript.cmd` **as administrator**.
6. Check the sensor service: `sc query sense` should show `STATE: 4 RUNNING`.
7. Wait 10 to 30 minutes. The device now shows as **Onboarded**.

In the screenshot below the status is onboarded 

<img width="1269" height="610" alt="onboarded confirmation" src="https://github.com/user-attachments/assets/5f229aad-fe5d-4ea5-9dca-fd8de4661308" />

### 3.3 Collect the investigation package
1. Go to **security.microsoft.com → Assets → Devices**, then open the device.
2. Click the **three dots** (upper right) → **Collect Investigation Package**.
3. Write a comment and click **Confirm**. (Other people in the organization can see this comment.)

<img width="1260" height="655" alt="collection package in red circl" src="https://github.com/user-attachments/assets/f85efc7b-d894-4b7d-ba36-5d75c2cd8746" />

 
4. Click the three dots → **Action center**.
5. The status is **Pending** at first. Refresh until the package is ready (it took longer than 10 minutes).
6. Download the zip file and unzip it.

 <img width="1273" height="613" alt="action center2" src="https://github.com/user-attachments/assets/7dce4a37-f0bd-409f-bf4d-474bc0064e3b" />


> Tip: collection can fail if the device has low battery or a metered connection.

### 3.4 Quick check with KQL (Advanced hunting)
```kusto
DeviceInfo
| where DeviceName startswith "abd"
| project Timestamp, DeviceName, OnboardingStatus, SensorHealthState
```
Before onboarding, `OnboardingStatus` was **Can be onboarded** and `DeviceProcessEvents` returned no rows. After onboarding, process events appeared.

---

## 4. What was in the package

| Folder or file | What it shows |
|---|---|
| `Forensics Collection Summary.csv` | Every command used, with status and error code |
| `Processes` | Processes running at collection time |
| `Network Connections` | Active connections, DNS cache, ARP, IP config |
| `Prefetch Files` | Evidence of programs that ran (even if closed or removed) |
| `Autoruns` | Registry data about auto-start items (also includes BAM data) |
| `Scheduled Tasks`, `Services` | Possible places for persistence |
| `Security Event Log` | Logons, failed logons, account and policy changes |
| `Installed Programs` | Software list from the registry |
| `Temp Directories` | Files in each user's Temp folder |
| `Users and Groups`, `SMB Session` | Local groups, signed-in users, shared sessions |
| `System Information` | OS version, boot time, network adapters |
| `WdSupportLogs` | Microsoft Defender Antivirus support logs |

unzipped investigation file
<img width="1268" height="751" alt="MDE investigation screenshot 1" src="https://github.com/user-attachments/assets/e034da5b-58c2-4367-a1d8-a1c5a35ed2c7" />

Autoruns
<img width="1265" height="721" alt="Autoruns" src="https://github.com/user-attachments/assets/a69a18a3-9979-4bb3-9f33-d586da56f6c1" />

Prefetch Files
<img width="1239" height="682" alt="prefetch" src="https://github.com/user-attachments/assets/66f8f5e8-563d-4314-a16b-b0633e679def" />


**Collection check:** `Forensics Collection Summary.csv` lists **70 commands, all `Completed`, error code 0.** The package is complete.


<img width="1274" height="634" alt="forensic collection summary " src="https://github.com/user-attachments/assets/a1a2c930-fd7d-4577-b826-9ad19b3ce0de" />

---

## 5. Findings in detail

### Finding 1: Many failed logons from the internet (High)
**Where I found it:** `Security Event Log/Security.evtx` (Event ID **4625**, failed logon)

| Item | Value |
|---|---|
| Failed logons from outside | **7,205** (logon type 3, network) |
| Time range (UTC) | 11 Oct 2026, 14:54 to 23:25 |
| Outside IP addresses | 6 |
| Top sources (masked) | `59.18.x.x` (2,527), `43.130.x.x` (2,455), `218.147.x.x` (993), `103.98.x.x` (748), `95.189.x.x` (481), `185.136.x.x` (1) |
| Most tried user names | `Administrator` (4,140), `admin` (1,612), then `aiuser`, `aiadmin`, `vmadmin`, `sqladmin`, `localadmin` and similar |
| Busiest time | 21:00 to 22:59 UTC (about 4,000 attempts) |
| Reason for failure | Almost all: "user name does not exist" (`0xC0000064`) |

**What it means:** This looks like automatic password guessing (brute force or password spraying) with common admin user names. The attempts reached the VM over the network, which suggests that a network service (such as RDP) was reachable from the internet. The event log does not say which port, so I need to check the VM's network rules.

**Did it work?** I checked successful logons (Event ID **4624**):
- No successful logon came from any of the 6 outside IPs.
- All successful logons came from internal `10.0.8.x` addresses, using the one admin account (13 remote desktop logons, type 10).
- No new accounts (Event 4720: 0), no group changes (Event 4732: 0), and the security log was not cleared (Event 1102: 0).
- Only `azure****1` is in the local Administrators group.

**Small note:** Two failed attempts used the user name `guest` with a "wrong password" result. That means the name exists as an account. It is normally disabled, but it is worth confirming.

**Recommended actions**
1. Do not expose RDP or other management ports to the internet. Allow access only through Azure Bastion, or a restricted source address.
2. Review the Network Security Group (NSG) and any public IP on the VM.
3. Use account lockout, strong passwords, and MFA where possible.
4. Rename or disable default admin names when possible.
5. In Defender, hunt for the same pattern:

```kusto
DeviceLogonEvents
| where DeviceName startswith "abd"
| where ActionType == "LogonFailed"
| summarize Attempts = count() by RemoteIP, AccountName
| sort by Attempts desc
```

---

### Finding 2: Tor Browser ran on the VM (Medium)
**Where I found it:** `Prefetch Files`, `Autoruns` (BAM data), `Temp Directories`

| Time (UTC, 11 Oct 2026) | Evidence |
|---|---|
| 01:59:58 | `tor-browser-windows-x86_64-portable-15.0.20.exe` ran from the user's Downloads folder (Prefetch) |
| 02:00:48 and 02:02:31 | `tor.exe` ran from `Desktop\Tor Browser\...` (Prefetch, 2 runs) |
| 02:00 to 02:02 | `firefox.exe` (the Tor Browser program) ran 11 times (Prefetch) |
| 02:01:01 and 02:02:55 | Last run times for the installer and Tor Browser (BAM registry data) |

**Why this matters for an analyst**
- Tor Browser is **portable**, so it did **not** appear in the *Installed Programs* list. If you only check installed software, you miss it. Prefetch and BAM caught it.
- Tor hides traffic, so DNS cache and connection lists may show nothing. Execution evidence is more useful here.
- In this lab the activity is expected. In a real company, an unapproved Tor use should be investigated.

---

### Finding 3: The live snapshot is clean (Info)
The package is a snapshot of the machine at **23:25 UTC**. The VM was restarted just before (boot time 23:20 UTC), so programs like Tor were no longer running.

| Area | Result |
|---|---|
| Processes (158) | Only Windows, Defender, Azure agent, Edge, OneDrive. The only `powershell.exe` was the collection command itself. |
| Network connections | Only Microsoft and Azure addresses, plus the RDP session from an internal `10.0.8.x` address |
| DNS cache | Only Microsoft and Windows Update names |
| ARP cache | Only the default gateway and standard multicast addresses |
| SMB sessions | None |
| Scheduled tasks | Only 3 non-Microsoft tasks, all OneDrive |
| Services | No service running from a user folder |
| Users | One signed-in user (`azure****1`), one local administrator |

> I reviewed `Autoruns` for Tor, Temp-folder or PowerShell items using keyword search. The only matches were the BAM entries in Finding 2.

---

### Finding 4: Defender onboarding changed the machine (Info)
- The onboarding script ran from the user's Temp folder at about **23:22 UTC** (seen in Temp Directories and CMD Prefetch).
- Defender sensor programs (`MsSense.exe`, `SenseIR.exe`, `SenseNdr.exe`, `SenseTVM.exe`) started at **23:22 to 23:23 UTC**.
- Windows **audit policy** was changed 12 times at **23:22:35 UTC** by the machine account (Event 4719). This is normal during onboarding.

---

## 6. Timeline (UTC)

| Date and time | Event | Source |
|---|---|---|
| 10 Oct, about 00:08 | VM created (earliest records) | System Information, Security log |
| 11 Oct 01:52 to 01:53 | Notepad ran 3 times | Prefetch |
| 11 Oct 01:59:58 | Tor Browser installer ran | Prefetch |
| 11 Oct 02:00 to 02:03 | Tor Browser ran | Prefetch, BAM |
| 11 Oct 14:54:13 | First failed logon from outside | Security log |
| 11 Oct 15:00 to 23:25 | Thousands of failed logons (peak 21:00 to 22:59) | Security log |
| 11 Oct 23:20 | VM restarted | System Information |
| 11 Oct 23:22 | Onboarding script ran, Defender sensor started | Temp, Prefetch, Security log |
| 11 Oct 23:25 | Investigation package collected (70 of 70 commands OK) | Collection summary |

> Note: all times are UTC. The VM's local time was about 7 hours behind.

---

## 7. Limits of this investigation
- The package is a **snapshot plus some history**. It does not include a full disk image or a memory dump.
- Before onboarding, Defender recorded **no** telemetry for this VM. History came only from Windows files (Prefetch, BAM, event log).
- The event log in this package starts at the VM's first boot on 11 Oct (UTC).
- I could **not confirm** the mentor's PowerShell test script. The package does not include `C:\ProgramData` files or script text. PowerShell ran 11 times in total, but I cannot tell which runs belong to the test. To confirm, check the script's log file on the VM.
- `InstalledPrograms.csv` was empty, so I used the registry text files in the same folder.

---

## 8. Lessons learned
1. A device must be **onboarded** before response actions (like *Collect Investigation Package*) work.
2. Your account needs the right **role** to download the onboarding package and run response actions.
3. Always check `Forensics Collection Summary.csv` first, to see if the package is complete.
4. Check **more than one source**. Tor was missing from Installed Programs but clear in Prefetch and BAM.
5. A package may show an unexpected risk. I came to look at Tor and found internet password guessing in the Security log.
6. Mask sensitive data (names, IPs, IDs) before sharing any write-up.

---

## 9. Tools used
- Microsoft Defender portal (Assets → Devices, Action center, Advanced hunting)
- Windows Command Prompt (`sc query sense`)
- Python (`python-evtx`, `libscca`) to read the event log and Prefetch files
- Microsoft documentation: *Collect investigation package from devices*

---

---

### Note on AI use
I did the lab myself: I set up the VM, onboarded it to Defender for Endpoint, and collected the investigation package. I used an AI assistant (Claude) to help me read the package files, organize the findings, and improve the wording of this write-up. I reviewed the content, and sensitive details are partly masked.
