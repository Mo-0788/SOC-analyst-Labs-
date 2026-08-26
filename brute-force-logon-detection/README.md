# Brute-Force & Suspicious Remote Logon Detection with KQL — Microsoft Defender Advanced Hunting 

## Table of Contents
## Overview
## Query 1 — Failed Logons / Brute-Force Detection
## Query 2 — Successful Logon Following Failures
## Query 3 — Remote Interactive Logons from External (Public) IPs
## Combined Findings — Connecting the Three Queries
## Conclusion — What Is the Threat?
## Recommended Next Steps

## 1.  Overview

This write-up covers three related KQL (Kusto Query Language) hunting queries run in Microsoft Defender Advanced Hunting, all built around the same table: DeviceLogonEvents.
Each query looks at logons from a different angle, and together they build a full picture of a login-based attack — starting broad, then narrowing in on what actually succeeded.  

<img width="432" height="182" alt="github screen of query " src="https://github.com/user-attachments/assets/60418358-0d21-44b0-8398-1064d773e014" />

Run in this order, these three queries take an analyst from "something looks noisy" → "did it actually work" → "who from the outside world is getting remote access, and is that normal."

## 2. Query 1 — Failed Logons / Brute-Force Detection 

// Set your investigation window once at the top, reuse it everywhere. or you can remove it in case you want all time which is a lot of data 
let startTime = datetime(2026-08-01 00:00:00);
let endTime   = datetime(2026-08-02 00:00:00);
// USE CASE 1: Failed logons / brute-force detection
// Counts failed attempts per account + source. A spike from one
// RemoteIP or against one account is a brute-force signal.
DeviceLogonEvents
| where TimeGenerated between (startTime .. endTime)
| where ActionType == "LogonFailed"
| summarize FailedCount = count(), Accounts = make_set(AccountName, 20)
    by RemoteIP, DeviceName, FailureReason
| where FailedCount > 10
| sort by FailedCount desc

<img width="1253" height="695" alt="brute-force query number one " src="https://github.com/user-attachments/assets/874be44a-01ed-4801-9db1-9c8133bc4272" />

 ### In simple English: 
 this query looks through the sign-in logs for a chosen time window and pulls out every logon attempt that failed. It then groups those failures by where the attempt came from (RemoteIP), which machine it targeted (DeviceName), and why it failed (FailureReason) — and counts how many failures happened in each group. 
 Any group with more than 10 failures gets kept and shown, worst offenders first.

When a SOC analyst uses it: as a first pass over a shift, a day, or an incident window, to answer "is anyone hammering a login prompt right now?" It's the starting point — it flags noise, not necessarily compromise.
What the result looks like: a table with RemoteIP, DeviceName, FailureReason, a FailedCount number, and an Accounts list — sorted so the noisiest source/target pair is at the top. (see the screenshot above)

## 3. Query 2 — Successful Logon Following Failures

let failures =
DeviceLogonEvents
    | where ActionType == "LogonFailed"
    | summarize Failures = count() by AccountName, DeviceName, RemoteIP;
let successes =
    DeviceLogonEvents
    | where ActionType == "LogonSuccess"
    | summarize Successes = count(), LastSuccess = max(TimeGenerated)
        by AccountName, DeviceName, RemoteIP;
failures
| join kind=inner successes on AccountName, DeviceName, RemoteIP
| where Failures > 10 and Successes > 0
| project AccountName, DeviceName, RemoteIP, Failures, Successes, LastSuccess
| sort by Failures desc

### In simple English:
this query answers the important follow-up question that Query 1 can't: did any of those brute-force attempts actually work? It builds two separate lists — one counting failed logons, one counting successful logons — for the same account, device, and source IP. 
Then it joins the two lists together and keeps only the rows where there were more than 10 failures AND at least 1 success from that exact same combination. That pattern — many failures, then a success — is a strong sign an account was cracked, not just probed.

<img width="1252" height="701" alt="failuresand then success all result with hidden IP " src="https://github.com/user-attachments/assets/93bb0afb-5b2f-4851-bec7-32866a80c995" />


When a SOC analyst uses it: right after running Query 1, to separate "this was just noise" from "this account may now be compromised." This is the query that turns a low-priority alert into a high-priority incident.

What the result looks like: a table with AccountName, DeviceName, RemoteIP, Failures, Successes, and LastSuccess (the timestamp of the successful logon) — sorted with the highest failure counts first.
this table is my real result of this query you can see the yellow highlighted is public IP address tried to get access as administrator 40 times and he gains the access one time.
<img width="776" height="640" alt="log table query 2 (try many time and get access)" src="https://github.com/user-attachments/assets/e1b3aa18-9ddf-4482-a259-6aae32f23059" />

Key observations in my table:
Six of the ten rows target the built-in administrator account specifically — attackers are guessing the default admin login, not random usernames. This is a textbook credential-stuffing / RDP brute-force pattern.
root on linux-scan-break-fix-learn from 10.#.#.# (a private/internal IP) is your internal vulnerability-scanning engine authenticating repeatedly as part of normal scanning behavior — this is benign, not an attack. High failure counts here are expected because scanners often test many credential combinations by design.
The annu and guest rows also come from internal/blank source IPs, consistent with internal automation/remediation accounts and lab test accounts rather than outside attackers.
The genuinely concerning rows are the ones with a public source IP: 95.217.###.##, 59.15.1##.##, 111.68.10#.###, 201.###.98.###, and 80.66.##.## — each brute-forced the administrator account dozens of times and then succeeded at least once.

## 4. Query 3 — Remote Interactive Logons from External (Public) IPs

DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive", "Network", "Unlock")
| where RemoteIPType == "Public"
| summarize count = count() by RemoteIP, DeviceName
| sort by ['count'] desc

### In simple English: 
this query looks only at logons that succeeded, filters to the types of logons that matter for remote access (RemoteInteractive — like RDP, Network — like accessing a shared drive, and Unlock — unlocking an already-open session), and then keeps only the ones where the source IP is public (i.e., coming from outside the organization's network, not an internal machine).
It counts how many times each public IP successfully logged into each device.

<img width="1262" height="707" alt="query specifieed for the external Ip who logon ssuccessful " src="https://github.com/user-attachments/assets/1e51da0e-57eb-45f1-a5b0-d0ebf08c6a35" />

As a SOC analyst  I use it to get a full picture of who from the outside world can — and does — reach company machines remotely. It's also the query that lets you cross-check: if an IP shows up here and it also appeared in Query 2's "brute-force that succeeded" list, that's confirmation the access wasn't a fluke.
### Findings from query 3:
1- 54 unique public IP addresses successfully logged into 31 different internal devices during the captured period — meaning the environment has real, active exposure to the public internet, not just theoretical risk.
2- Most of these are almost certainly legitimate remote staff — high, steady logon counts from one IP into one personally-named device (e.g. 73.45.@@.# → adam-vm with 25 logons, 89.45.#.## → ###-vm with 18 logons, 98.147.249.### → ###ce-vm). One person, one machine, a normal daily pattern — this looks like people working from home via RDP.
3- A smaller set of IPs stand out because they don't fit that pattern — one external IP reaching multiple different, unrelated corporate machines:

## 5. Combined Findings — Connecting the Three Queries 

80.6#.##.## this IP is the most serious finding in this data set. It touched 4 separate corporate devices (Query 3), and on one of them — corp-na01-26 — it also appears in Query 2's results with 19 failed logons followed by 2 successful logons as the administrator account.
This is a single external actor that tried multiple machines and successfully broke into at least one of them.
95.217.##.### attacked the administrator account on two different devices (corp-378-204 and corp-na09-fe9), 40 failures each, succeeding once on both — the same external actor running the same attack against multiple targets.
59.15.###.##, 111.68.###.###, and 201.187.##.### each ran the same pattern — dozens of failed administrator login attempts followed by exactly one success — against a single device each.
By contrast, the high-volume entries in Query 3 (25, 18, 15, 12 logons from one IP to one personally-named VM) do not appear anywhere in the brute-force/success join — meaning no pile of failures preceded them.
That's consistent with normal, legitimate remote access rather than an attack.
The 1#.#.#.# entry (internal IP, root account, on the vulnerability-scanning host) is the one high-failure/high-success row that is expected and benign — it's the organization's own scan engine, not an external threat.

## 6. Conclusion — What Is the Threat?

Put together, these three queries show that the environment is being actively targeted from the public internet, and that the attackers are not just knocking — some of them got in.

### The pattern:
multiple external, unrelated public IP addresses are running automated brute-force attempts specifically against the built-in administrator account across several internet-facing devices.
### The outcome:
at least five distinct public IPs succeeded in logging in after dozens of failed attempts — most seriously 80.##.##.##, which spread its attempts across four different machines and still broke through on one.
### The false alarm to rule out:
the internal scan engine (1#.#.#.#) produces the highest raw failure/success numbers in the whole data set, but it is normal internal security-tooling behavior, not an attacker — correctly separating this from the real external threats is what keeps the investigation focused on what actually matters.
### Bottom line:
this is not a single isolated brute-force attempt — it's a pattern of credential-guessing against a shared, high-value account (administrator) from multiple external sources, with confirmed successful access on at least one internal machine. This should be treated as an active compromise, not just a suspicious trend.

## 7. Recommended Next Steps
### Immediately isolate and investigate:
corp-n##-@@ — confirmed successful administrator logon from 80.##.##.## after repeated failures.
### Force a password reset on:
the built-in administrator account across every affected device, and disable it in favor of named admin accounts wherever possible.
### Block or restrict the identified public IPs:
(80.##.##.##, 95.217.##.###, 59.##.###.##, 111.68.###.###, 201.187.##.###) at the firewall/NSG level.
### Remove direct public internet exposure for:
RDP/remote-logon ports where possible — put remote access behind a VPN or a jump host instead of exposing servers directly.
### Add a scheduled detection rule based on Query 2"
(failures-then-success join) so any future successful brute-force is flagged automatically instead of found through manual review.

this is one of the IP was attacking the network see in the red highlighted how suspicious he is (60 of 100) that`s serious threat

<img width="1259" height="698" alt="highited suspicious public IP attacking cyber range nework " src="https://github.com/user-attachments/assets/dda992f8-ba72-4701-b9e1-68a4612896b2" />

this is one of the attacker IP address from Poland 

<img width="1269" height="701" alt="public IP attacking cyber range fron poland " src="https://github.com/user-attachments/assets/980751c9-7197-4371-aea7-27f2442df5dc" />






