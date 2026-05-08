---
title: 'SPLUNK Lab: Brute Force and Unauthorized Login Detection'
author: bit01net
date: 2026-05-06
categories: [HomeLab]
tags: [SPLUNK]
image:
  path: /assets/images/splunk_small/show.png
---

In this blog, we will simulate a brute-force attack in an Active Directory lab using Kali Linux, detect the activity in Splunk using Windows Security logs, create detection queries for failed and successful logins, and convert those queries into scheduled alerts for early detection and monitoring.

**LAB SET UP:**
Windows 10,  Domain Controller (DC), Splunk, Kali Linux

## Attack Simulation
Before brute-forcing, I performed a scan to confirm the required port was open.

Brute force attacks are noisy and easily detectable, but they are still widely used in real environments.
I used netexec to brute-force SMB authentication because RDP is often disabled by default, while SMB is commonly enabled in Active Directory environments.

```
netexec smb 10.0.2.13 -u Billy -p /usr/share/wordlists/rockyou.txt -d BLUE.local --ignore-pw-decoding
```
Command Breakdown
`netexec `→ offensive networking/authentication tool
`smb` → attempts SMB authentication
`-u Billy` → target username
`-p rockyou.txt` → password wordlist
`-d BLUE.local` → target domain
`--ignore-pw-decoding` → suppress decoding-related errors

![](/assets/images/splunk_small/Brute_force.png) 

Within seconds, the tool generated a very high number of authentication attempts.

Eventually, valid credentials were discovered.


## Detection in Splunk

### Brueforce
Open Splunk and click on "Search & Reporting". select the appropriate time range, Since I already knew the target host, I included it in the search.
```
index=windows host="Client-01" sourcetype="WinEventLog:Security" EventCode=4625 
| stats count by Account_Name, Source_Network_Address, Failure_Reason
```
![](/assets/images/splunk_small/bf_detect.png)

With this query, we observed `142` failed logon attempts within a very short period of time against the `Billy` account from `10.0.7.6`, which is highly suspicious

### Successful Login
A brute-force attack main goal is to gain Valid credentials which gives access to attackers

So after identifying repeated failed logins, the next step is checking whether the attacker eventually gained access to **Billy user account from this IP 10.0.7.6**.

Successful logons generate: `Event ID 4624`
```bash
index=windows host="Client-01" sourcetype="WinEventLog:Security" EventCode=4624 Account_Name!="*$" Account_Name!="ANONYMOUS LOGON" Source_Network_Address="10.0.2.6"
| table _time Account_Name Source_Network_Address Logon_Type
```

![](/assets/images/splunk_small/success_from_that_ip.png)

The Event shows that the attacker successfully authenticated to the Billy account from 10.0.2.6 at this time, confirming that the brute-force attack eventually succeeded. The **Logon_Type value 3 indicates a network logon**, commonly associated with SMB authentication.

---
Above we did triggerd BruteForce against single user and login with Same IP

Instead of investigating only after an incident happens, we can build alerts to detect suspicious activity early.

For larger environments and broader detection coverage:

- remove host-specific filters to monitor all systems
- detect brute-force attempts based on threshold counts
- monitor logins from unknown or unauthorized IP addresses

---

So, based on above ideology, let’s create queries to detect this activity if it happens again.

## Rule 1 — Brute Force Detection
This query detects if ther are **more than 5 failed login attempts within 3 minutes from the same IP against a user account**

```bash
index=windows sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type IN (3,10)
Source_Network_Address!="-" 
| bucket _time span=3m 
| stats count by Source_Network_Address Account_Name Logon_Type
| where count > 5
```

## Rule2: Unauthorized Access
This query detects successful logins from IP addresses other than the trusted/allowed IPs listed in the query.

```bash
index=windows sourcetype="WinEventLog:Security" EventCode=4624
Logon_Type IN (3,10)
Account_Name!="*$"
Account_Name!="ANONYMOUS LOGON"
NOT Source_Network_Address IN ("10.0.2.13","10.0.2.10","10.0.2.10","127.0.0.1","::1","-")
| table _time Account_Name, ComputerName, Source_Network_Address, Logon_Type
```
## Save as Alerts

After confirming the query detected the simulated activity successfully, click `Save As → Alert` at the top-right corner.
![](/assets/images/splunk_small/save_query.png)

Then, based on what the query is detecting, give the alert an appropriate name and description so it is easy to understand later during investigations or monitoring.

![](/assets/images/splunk_small/BF_alert_create.png)

Now you can fill the details depending on your environment and detection needs: environment size, log volume,
how quickly you want alerts to trigger.
For this Lab. I chose:
`Alert type = scheduled` → to make Splunk run the query automatically at specific intervals

`Time Range= Last 24 hours` -> searches logs generated within the last 24 hours.

`cron expression: * * * * * `→ runs the query every minute to detect suspicious activity quickly

Under the Trigger Actions section:

- choose Add to Triggered Alerts
- select the severity level
- save the alert

![](/assets/images/splunk_small/trigger_alerts_login2.png)

If you go to `Triggered alerts` cron job will query last 24 windows every minute - for both activities
and did generated alerts.
![](/assets/images/splunk_small/both_alerts_2.png)

If you click on `Open in Search`, Splunk runs the saved query again and shows the matching event details.

---

Understanding Triggered Alerts:

Even though the alerts were configured with a 24-hour time range and set to run every minute, only 2 alerts appeared under Triggered Alerts for each rule.

At first, I expected Splunk to create a new alert every minute since the query runs every minute. But Splunk works differently. Running the query every minute only means Splunk checks the condition every minute — it does not always generate a brand-new alert every time if the same matching events are already included within the alert time window.

---



