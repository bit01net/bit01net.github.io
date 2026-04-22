---
title: 'Volt Typhoon'
author: bit01net
date: 2026-04-11
categories: [SOC Investigation]
tags: [Tryhackme, SPLUNK]
image:
  path: /assets/images/volt-typh/room-show.png
---

Scenario: The SOC has detected suspicious activity indicative of an advanced persistent threat (APT) group known as Volt Typhoon, notorious for targeting high-value organizations. Assume the role of a security analyst and investigate the intrusion by retracing the attacker's steps.

You have been provided with various log types from a two-week time frame during which the suspected attack occurred. Your ability to research the suspected APT and understand how they maneuver through targeted networks will prove to be just as important as your Splunk skills. 

For the investigaiton, we have Three type of Logs
![](/assets/images/volt-typh/logs_we_have.png)

### Initial Access
Volt Typhoon often gains initial access to target networks by exploiting vulnerabilities in enterprise software. In recent incidents, Volt Typhoon has been observed leveraging vulnerabilities in Zoho ManageEngine ADSelfService Plus, a popular self-service password management solution used by organizations.
```
* sourcetype=adss ip_address="192.168.1.134" | table _time, ip_address, action_name, username
```
![](/assets/images/volt-typh/account_access.png)

I started with the ADSelfService Plus logs and focused on the IP address field. One IP — 192.168.1.134 — stood out because it had higher activity compared to others.

Looking closer at this IP, several sensitive actions were observed:

From the logs, it shows that the attacker gained access to an existing account `dean-admin` and changed its password at `2024-03-24T11:10:22`.

Two minutes later, a new account named `voltyp-admin` was created. This account then went through multiple setup actions, including enrollment, password change, security question setup, and MFA configuration.

This sequence shows that after gaining access to the initial account, the attacker established `persistence` by creating and configuring a new administrative account.

### Execution
Volt Typhoon is known to exploit `Windows Management Instrumentation Command-line (WMIC)` for a range of execution techniques. They leverage WMIC for tasks such as gathering information and dumping valuable databases, allowing them to infiltrate and exploit target networks. By using "living off the land" binaries (LOLBins), they blend in with legitimate system activity, making detection more challenging.

![](/assets/images/volt-typh/cmd_account_create.png)

We can see in the WMIC logs the creation of the voltyp-admin user, which we also observed earlier in the ADSelfService Plus logs.

```
* sourcetype=wmic username="dean-admin" | table _time, ip_address, username, command
```
After setting the time range to when access to the dean-admin account was gained, several suspicious commands start appearing in the logs.

![](/assets/images/volt-typh/ADdumptoweb.png)

From the WMIC logs under the dean-admin account, the attacker first performs basic reconnaissance to understand the system and available resources.

They then create a copy of the Active Directory database using **ntdsutil**, storing it in `C:\Windows\Temp\tmp`, where it appears as `temp.dit`.

The file temp.dit is copied to the web server directory `\webserver-01\c$\inetpub\wwwroot`, placing it in `C:\inetpub\wwwroot` for easier access.

After that, the file is **compressed and password-protected** into `cisco-up.7z`, still inside C:\inetpub\wwwroot.

Finally, the archive cisco-up.7z is **renamed** to `cl64.gif` in the same directory, disguising it as a normal image file.


### Persistence
Our target APT frequently employs web shells as a persistence mechanism to maintain a foothold. They disguise these web shells as legitimate files, enabling remote control over the server and allowing them to execute commands undetected.
---
While exploring the C:\Windows\Temp directory activity, PowerShell logs show the attacker writing encoded content into a file named ntuser.ini. using echo command

After that, the attacker uses `certutil -decode` to decode the contents of ntuser.ini and writes the output to `iisstart.aspx`.

This shows that the attacker is taking encoded data, storing it locally, and then decoding it into an .aspx file, likely preparing a web shell for execution.

![](/assets/images/volt-typh/webshell_code.png)



### Defense Evasion
Volt Typhoon utilizes advanced defense evasion techniques to significantly reduce the risk of detection. These methods encompass regular file purging, eliminating logs, and conducting thorough reconnaissance of their operational environment.

- #### Clearing RDP Artifacts
In an attempt to cover their tracks, the attacker clears RDP-related records using `Remove-ItemProperty -Path $registryPath -Name MRU -ErrorAction SilentlyContinue`, which removes the “Most Recently Used” entries from the registry. 
![](/assets/images/volt-typh/RDP_logs_remove.png)
Here, `$registryPath` represents the registry location where RDP connection history is stored, so this command effectively deletes evidence of previously accessed remote systems.
![](/assets/images/volt-typh/path.png)


- #### Virtual Environment Detection
the attacker querying the registry path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control` and filters for any properties related to `“Virtual”`. This indicates the attacker is checking for signs of a virtualized environment, such as a VM or sandbox, before proceeding further.
![](/assets/images/volt-typh/check_for_vm.png)

 

### Credential Access
Volt Typhoon often combs through target networks to uncover and extract credentials from a range of programs. Additionally, they are known to access hashed credentials directly from system memory.
---
- #### Credential Source Enumeration
Using reg query, the attacker searches the registry for installed software and stored configurations that may contain useful credentials. From the logs, they specifically look into OpenSSH, RealVNC, and PuTTY.
These are all remote access tools, and attackers often target them because they can store connection details, usernames, or keys. By querying these registry paths, the attacker is trying to identify saved sessions or configurations that could help them move laterally or reuse credentials.
![](/assets/images/volt-typh/softwares_exist.png)
- #### Credential Dumping via Mimikatz
In a later step, a base64-encoded PowerShell command is observed (decoded using CyberChef), which reveals that the attacker downloads mimikatz.exe to C:\Temp\db2\mimikatz.exe and executes it against lsass.dmp to extract credentials. This shows credential dumping activity as part of the attack chain.
![](/assets/images/volt-typh/mimikatzcode.png)
![](/assets/images/volt-typh/mimikatzdwn.png)

### Discovery
Volt Typhoon uses enumeration techniques to gather additional information about network architecture, logging mechanisms, successful logins, and software configurations, enhancing their understanding of the target environment for strategic purposes.
---
From these wevtutil commands, the attacker is repeatedly querying Windows Security logs on a daily basis.
![](/assets/images/volt-typh/logsenum_clear.png)
They are using wevtutil qe security with filters for specific Event IDs like `4624, 4625, and 4769`, which relate to logons, failed logons, and authentication activity. The queries are also filtered by usernames like **admin, MSSQLSvc, and systems like workstation01 or IP ranges such as 192.168.1.*.**

This shows that the attacker is continuously monitoring authentication activity in the environment, likely to track valid logins, identify useful accounts, and spot opportunities for lateral movement or privilege use.

### Lateral Movement
The APT has been observed moving previously created web shells to different servers as part of their lateral movement strategy. This technique facilitates their ability to traverse through networks and maintain access across multiple systems.
---
![](/assets/images/volt-typh/copytoweb.png)
After creating a web shell, the generated web shell at C:\Windows\Temp\iisstart.aspx is then **copied to \server-02\c$\inetpub\wwwroot\AuditReport.jspx**, showing lateral movement to Server-02 and placement in a web-accessible directory under a **renamed** file.

### Collection
During the collection phase, Volt Typhoon extracts various types of data, such as local web browser information and valuable assets discovered within the target environment.
---
The attacker identifies critical financial data in C:\ProgramData\FinanceBackup\, then copies files `2022.csv, 2023.csv, and 2024.csv` from that directory to C:\Windows\Temp\faudit\, staging the files for exfiltration of sensitive data.
![](/assets/images/volt-typh/exfil_cmd.png)

### C2
Volt Typhoon utilizes publicly available tools as well as compromised devices to establish discreet command and control (C2) channels.
---
the attacker sets up a C2 channel using netsh portproxy, forwarding traffic **from port 50100 on the compromised host** to `10.2.30.1:8443`, establishing a covert communication path. Later, this port forwarding rule is **deleted**, indicating cleanup after use.
![](/assets/images/volt-typh/C2.png)

### Cleanup
To cover their tracks, the APT has been observed deleting event logs and selectively removing other traces and artifacts of their malicious activities.

Toward the end, the attacker runs `wevtutil cl Application Security Setup System`, which clears multiple event logs, indicating an attempt to remove evidence of their activity.

### Summary

The activity starts with a password change on the dean-admin account, which turns out to be the attacker’s entry point. Soon after, a new administrative user voltyp-admin is created, showing that access has been secured for persistence.

The attacker then begins exploring the environment using WMIC and collects Active Directory data using ntdsutil, preparing it for movement by compressing and protecting it. At the same time, a web shell is built from encoded content, converted into an .aspx file, and later moved to Server-02 under a different name to maintain access.

To avoid detection, traces of activity are removed by clearing RDP history and deleting logs, while also checking whether the system is running in a virtual environment. The attacker also searches the registry for stored credentials from tools like OpenSSH, PuTTY, and RealVNC, and uses Mimikatz to extract credentials from memory.

With broader access, the attacker targets sensitive data, identifying financial files FinanceBackup and copying them for exfiltration. A covert channel is then set up using port forwarding to communicate with an internal system.
