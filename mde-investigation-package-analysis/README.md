
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

