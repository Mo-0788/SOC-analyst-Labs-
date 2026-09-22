Port Scan Detection with KQL — Microsoft Defender Advanced Hunting

1. Overview
This investigation uses KQL (Kusto Query Language) in Microsoft Defender's Advanced Hunting module to detect a classic network-security pattern: one source IP touching an unusually large number of distinct destination ports — the signature of a port scan.

Table used: NTANetAnalytics (network traffic/flow logs)
Workspace:  (a controlled lab/range environment)
Investigation window: 2026-06-02 00:00 → 2026-06-03 00:00
Result: 41 matching rows, with one internal host standing out clearly from the rest (see Findings).

2. The Query

```kusto
// Set your investigation window once at the top, reuse it everywhere.
let startTime = datetime(2026-06-02 00:00:00);
let endTime   = datetime(2026-06-03 00:00:00);
NTANetAnalytics
| where TimeGenerated between (startTime .. endTime)
| where FlowStatus == "Allowed"
| where isnotempty(SrcIp)
| summarize DistinctPorts = dcount(DestPort), Ports = make_set(DestPort, 50) by SrcIp, DestIp, AclRule
| where DistinctPorts > 50
| sort by DistinctPorts desc
```

3. Line-by-Line Breakdown (for beginners)
let startTime = datetime(2026-06-02 00:00:00);
let endTime = datetime(2026-06-03 00:00:00);

let creates a reusable variable. Instead of typing a fixed date into every filter, you define it once at the top and refer to it by name everywhere else. This is good practice because if you need to shift the investigation window, you only change it in one place instead of hunting through the whole query.

NTANetAnalytics

This names the table the query reads from. NTANetAnalytics stores network traffic flow records — who talked to whom, over which port, and whether the connection was allowed or blocked. Every query starts by naming its source table.

| where TimeGenerated between (startTime .. endTime)

The | (pipe) means "take the result so far and feed it into the next step." where filters rows. between (x .. y) keeps only rows whose timestamp falls inside that range — this is how the query stays scoped to the one-day window instead of scanning the whole table's history.

| where FlowStatus == "Allowed"

Keeps only traffic that the firewall/NSG actually let through. This matters: a scanner probing thousands of ports isn't interesting on its own — what's alarming is that the network allowed that many connections. == is an exact, case-sensitive match (see the note on == vs =~ below).

| where isnotempty(SrcIp)

A basic data-quality filter. It discards any row where the source IP field is blank/null, so those rows don't pollute the aggregation or throw off counts in the next step.

| summarize DistinctPorts = dcount(DestPort), Ports = make_set(DestPort, 50) by SrcIp, DestIp, AclRule

This is the heart of the detection logic. summarize ... by groups rows into buckets — here, one bucket per unique combination of (source IP, destination IP, firewall rule that allowed it). For each bucket it calculates two things:

dcount(DestPort) — a distinct count: how many different destination ports this source touched on this destination. This is the actual port-scan signal — a normal client usually touches one or a handful of ports (e.g. 443 for HTTPS); a scanner touches dozens, hundreds, or thousands.
make_set(DestPort, 50) — collects up to 50 of the actual port numbers into a list, so an analyst can see which ports were hit, not just the count.

Where beginners slip: confusing count() with dcount(). count() counts rows (which could just mean "50 packets to the same port"). dcount() counts unique values — which is what actually indicates scanning behavior.

| where DistinctPorts > 50

The detection threshold. Any source/destination pair that touched more than 50 distinct ports is flagged. This number is a judgment call — normal business traffic almost never legitimately needs 50+ different ports to one host, so it's a reasonable line between "normal chatter" and "someone/something is scanning."

| sort by DistinctPorts desc

Orders the results with the most extreme scanners at the top (desc = descending, highest value first), so the worst offenders are immediately visible instead of buried in the list.

Expected result of this query

A table where each row represents one attacker→target relationship, showing exactly how many unique ports were touched and which ones — ranked so the most aggressive scanning shows up first.

4. Findings

<img width="1271" height="701" alt="port scann result" src="https://github.com/user-attachments/assets/bf2d9039-6b86-48a3-bad2-21601a7383fc" />


Out of 41 result rows, the data splits cleanly into two very different groups:

Behavior	Distinct-port range	What it means
17 rows from one internal host	4,648 – 4,842 distinct ports per destination	Textbook, large-scale, multi-target port scan
Remaining rows (various sources)	56 – 162 distinct ports	Much smaller — plausibly response/reply traffic, still worth reviewing, but far less severe
🚨 Primary finding: internal host running a mass port scan

Source IP: 1#.#.#.8

This single host swept 17 different internal destination IPs, hitting thousands of distinct ports on each one — this is not normal application traffic. Real services use a small, fixed set of ports (e.g., 443, 3389, 445). Touching 4,000+ ports on a single destination in a 24-hour window is the definition of a scan.

Top 10 targets hit by 1#.#.#.8 (destination IPs partially masked — see security note below):

Destination (masked)	Distinct Ports Hit	Matching Firewall Rule
10.xx.0.32	4,842	danger-allow-all-inbound
10.xx.0.4	4,826	danger-allow-all-inbound
10.xx.0.26	4,824	scan_engine_allow_all_outbound
10.xx.0.38	4,822	scan_engine_allow_all_outbound
10.xx.0.35	4,816	danger_allow_all_inbound
10.xx.0.12	4,807	scan_engine_allow_all_outbound
10.xx.0.42	4,806	scan_engine_allow_all_outbound
10.xx.0.12	4,803	danger-allow-all-inbound
10.xx.0.104	4,660	allow_all_inbound_from_scan_engine
10.xx.0.110	4,648	scan_engine_allow_all_outbound

(7 more destinations were hit with 56–89 distinct ports each — smaller but still on the same source's pattern of touching every target it can reach.)

Ports observed include: a mix of well-known service ports (22 SSH, 80/443 HTTP/S, 135/139/445 SMB/RPC, 3389 RDP, 1900 SSDP, 5060 SIP) alongside large blocks of high, sequential, and unrelated ephemeral ports (e.g. 38293, 41524, 49664–49677) — the sequential/high-port sweeping is a strong scanner fingerprint, since real applications don't organically use thousands of sequential ports.

⚠️ What makes this especially dangerous

The firewall/NSG rules that allowed this traffic are named things like:

danger-allow-all-inbound
danger_allow_all_inbound
danger_danger_allow_all
scan_engine_allow_all_outbound
allow_all_inbound_from_scan_engine

These rule names are effectively self-labeled "allow everything" rules. The scan wasn't blocked or throttled by network policy — it succeeded on every single target because the surrounding firewall rules permit all traffic in both directions. This turns what could have been a contained, alert-worthy probe into a fully successful internal reconnaissance sweep across 17 hosts.

Secondary observation: low-volume "reverse" traffic

Rows where the destination IPs from above appear as the source, talking back to 1#.#.#.8 under a rule called platformrule, show much smaller distinct-port counts (56–162). This pattern is consistent with normal reply/response traffic generated as a side effect of the scan (targets replying on ephemeral ports), not a second attacker. It's included in the results because the same dcount(DestPort) > 50 threshold catches it too — worth knowing so it isn't mistaken for a second scanning host.

5. A Note on IP Masking

All destination IPs shown in this write-up have the second octet masked (e.g. 10.xx.0.32) before publishing to GitHub. Even though these addresses are private/internal (RFC 1918) space and not publicly routable, masking avoids exposing the internal network's addressing scheme or segment layout to anyone who might read this repository. The source IP (1#.#.#.8) is left unmasked intentionally, since identifying the attacking host is the entire point of the detection.

6. Conclusion

Which ports were scanned? Thousands of distinct ports per target — ranging from well-known service ports (22, 80, 443, 445, 3389) to large blocks of high/ephemeral ports — consistent with an automated, exhaustive port sweep rather than a targeted service check.

Who is the source? A single internal host, 1#.#.#.8.

How dangerous is it?

High risk. This is not a low-and-slow probe of one target — it's a mass internal port scan against 17 separate hosts, each swept for 4,600+ unique ports on the worst-hit targets.
The scan was not blocked: the NSG rules permitting the traffic are literally named danger-allow-all-inbound / allow_all_inbound_from_scan_engine, meaning the environment's own firewall policy let the entire sweep through unimpeded.
Combined, this indicates either (a) a compromised or misconfigured internal host actively performing reconnaissance ahead of a further attack (lateral movement staging), or (b) — given the rule names referencing "scan_engine" — a sanctioned vulnerability/security scanning tool running in this lab range. In a real production environment, this same pattern from an unrecognized host should be treated as a critical incident: isolate the host, review what it's authenticated as, and tighten the "allow-all" rules that let the scan succeed in the first place.

Recommended next steps:

Confirm whether 1#.#.#.8 is an authorized scanning/security tool (the scan engine_* rule names suggest this may be a sanctioned scanner in this range) — if not authorized, isolate the host immediately.
Replace the *-allow-all-* NSG rules with least-privilege rules scoped to only the ports each service actually needs.
Add an alert/detection rule based on this exact query (DistinctPorts > 50 from a single source) so future scans — authorized or not — are flagged automatically instead of found manually.
