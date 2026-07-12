# Threat-Hunting-Scenario-EMBERFORGE-Source-Leak

## RDP Compromise Incident

**Report ID:** INC-2026-3112

**Analyst:** Nadezna Morris

**Date:** 31-January-2026

**Incident Date:** 13-December-2025

---

## Executive Summary

----

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Type           | Indicator                                                                                                    |
| -------------- | -------------------------------------------------------------------------------------------------------------|

---

***FLAG 0: Environment Access***

**Objective:** Confirm you have access. What is the name of the custom log table containing the investigation data?

**Flag:** `EmberForgeX_CL`
```

```

---

***FLAG 1: Target Directory***

**Objective:** The attacker needed to package data before stealing it. The compression commands reveal exactly what they were targeting. What directory was the source of the stolen data?

**Flag:** `C:\GameDev`
```

```

---

***FLAG 2: Exfil Destination***

**Objective:** The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details. What cloud provider received the data?

**Flag:** `mega`
```

```

---

***FLAG 3: Attacker Attribution***

**Objective:** Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line. What email account was used to authenticate to the cloud service?

**Flag:** `jwilson.vhr@proton.me`
```

```

---

***FLAG 4: Domain Compromise Evidence***

**Objective:** This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file. This file contains every credential in the domain. What was it?

**Flag:** `ntds.dit`
```

````

---

***FLAG 5: Exfil Tool***

**Objective:** A cloud synchronisation tool was used to upload data externally. This tool is legitimate software commonly abused by threat actors. It was executed multiple times, not all successfully.

**Flag:** `rclone.exe`
```

```

---

**FLAG 6: Exfil Destination IP***

**Objective:** The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3). What IP address received the stolen data?

**Flag:** `66.203.125.15`
```

```

---

***FLAG 7: Attacker Credential Exposure***

**Objective:** The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution method exposed credentials far more recklessly than the others. Compare all executions and find the plaintext password.

**Flag:** `Summer2024!`
```

```

---

***FLAG 8: Archive Method***

**Objective:** Before exfiltration, the stolen data was compressed into an archive. The attacker used a built-in OS capability rather than third-party tools. This is a Living Off The Land technique. What cmdlet created the archive?

**Flag:** `Compress-Archive`
```

```

---

***FLAG 9: Staging Server***

**Objective:** The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

**Flag:** `sync.cloud-endpoint.net`
```

```

---

***FLAG 10: Malicious File***

**Objective:** The incident started with Lisa opening something from her desktop. Find the earliest malicious process creation event on the workstation. A Windows utility was used to load a file that does not belong in a normal user workflow.

**Flag:** `review.dll`
```

```

---

***FLAG 11: Delivery Vector***

**Objective:** Look at the full path of the malicious file. The drive letter is significant. If the file is not on C:, consider how it got there. Mounted disk images (ISO, IMG, VHD) appear as virtual drives and bypass certain Windows security protections.

**Flag:** `D:`
```

```

---

***FLAG 12: Compromised User***

**Objective:** The User field in process creation events tells you which account executed the payload. This is patient zero.

**Flag:** `lmartin`
```

```

---

***FLAG 13: Execution Chain***

**Objective:** Every process has a parent, and that parent has a parent. Trace the full execution chain from the user action through to the malicious file being loaded.

**Flag:** `Explorer.EXE > rundll32.exe > review.dll`
```

```

---

***FLAG 14: Delivery Unpacking***

**Objective:** Before the malicious DLL was loaded, the user opened a downloaded archive. A compression tool extracted its contents to a folder in the user's profile. This extraction step came before the DLL execution.

**Flag:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`
```

```

---

***FLAG 15: Dropped Payload***

**Objective:** Shortly after the initial DLL execution, a new executable appeared in a world-writable directory on the workstation. This became the attacker's primary tool for the rest of the operation.

**Flag:** `C:\Users\Public\update.exe`
```

```

---

***FLAG 16: C2 Domain***

**Objective:** The malware needs to communicate with the attacker. Sysmon EventCode 22 captures every DNS query a process makes. The domain will look designed to blend in with legitimate cloud traffic.

**Flag:** `cdn.cloud-endpoint.net`
```

```

---

***FLAG 17: Primary C2 IP***

**Objective:** DNS queries resolve domains to IP addresses. The QueryResults field inside the EventCode 22 raw XML contains the resolved IPs. You will need to parse Raw_s.

**Flag:** `104.21.30.237`
```

```

---

***FLAG 18: Injection Chain***

**Objective:** The attacker injected code from one process into another to hide. Sysmon EventCode 8 (CreateRemoteThread) captures this. Trace the injection chain.

**Flag:** `rundll32.exe > notepad.exe`
```

```

---

***FLAG 19: UAC Bypass Binary***

**Objective:** Certain Windows executables are trusted to auto-elevate without a UAC prompt. Attackers hijack what these binaries execute via registry modifications. Look for registry changes (EventCode 13) followed immediately by a trusted binary execution.

**Flag:** `fodhelper.exe`
```

```

---

***FLAG 20: Registry Bypass Enabler***

**Objective:** The UAC bypass works by creating a specific registry value that redirects execution. Two modifications were made in quick succession. One set the payload path. The other enables the hijack. What is that value name?

**Flag:** `DelegateExecute`
```

```

---

***FLAG 21: Stable Injection Chain***

**Objective:** After the UAC bypass, the elevated beacon performed a second injection for long-term stability. The source process was different from the first injection, and the target was running in a completely different security context.

**Flag:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`
```

```

---

***FLAG 22: Credential Dumping Process***

**Objective:** LSASS holds credentials for every logged-in user. The attacker dumped its memory to disk. The dumping tool used direct syscalls to bypass API monitoring. You will NOT find ProcessAccess events (EventCode 10) for LSASS. What process created the dump file?

**Flag:** `update.exe`
```

```

---

***FLAG 23: Dump Location***

**Objective:** You identified the process. Now find where it wrote the output. File creation events (EventCode 11) track every file written to disk. Where was the credential dump written?

**Flag:** `C:\Windows\System32\lsass.dmp`
```

```

---

***FLAG 24: User Enumeration***

**Objective:** The first command in the discovery sequence queries all user accounts in the domain.

**Flag:** `net user /domain`
```

```

---

***FLAG 25: Privilege Enumeration*** 

**Objective:** Immediately after listing users, the attacker queried a specific group to identify who has the highest level of access.
net group "Domain Admins" /domain

**Flag:** `net group "Domain Admins" /domain`
```

```

---

***FLAG 26: Infrastructure Mapping***

**Objective:** The final discovery command locates critical infrastructure. The attacker needs to know where to go next.

**Flag:** `nltest /dclist:emberforge.local`
```

```

---

***FLAG 27: Tool Staging Share***

**Objective:** Before moving laterally, the attacker set up the workstation as a distribution point. A network share was created.

**Flag:** `cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"`
```

```

---

***FLAG 28: Firewall Manipulation***

**Objective:** The workstation's firewall was blocking inbound connections needed for lateral movement. A rule was added. What name was given to the firewall rule?

**Flag:** `SMB`
```

```

---

***FLAG 29: Post-Escalation Parent***

**Objective:** After the beacon migrated to a SYSTEM process, all subsequent attacker commands on the workstation were executed as children of that process. Look at the parent process of the lateral movement commands (share creation, file copies, firewall changes).

**Flag:** `spoolsv.exe`
```

```

---

***FLAG 30: Beacon Distribution***

**Objective:** The attacker pushed their primary tool to the server via Windows admin shares (C$). What was the full command?

**Flag:** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`
```

```

---

***FLAG 31: LOLBin Tool Staging***

**Objective:** On the server, a built-in Windows utility was abused to download tools from the attacker's staging infrastructure. What utility was used, and what was the full URL it downloaded from?

**Flag:** `certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe`
```

```

---

***FLAG 32: Remote Execution Evidence***

**Objective:** Now look at the server. The attacker used a remote execution technique that creates temporary Windows services with random names. These appear in EventCode 7045 in Raw_s.

**Flag:** `MzLblBFm`
```

````

---

***FLAG 33: First Command on Server***

**Objective:** The remote execution technique redirects command output to temporary files. The very first attacker command on any newly compromised host is almost always the same.

**Flag:** `whoami`
```

```

---

***FLAG 34: Failed Lateral Movement***

**Objective:** The attacker's first lateral movement method was unreliable. Authentication logs on the server show repeated failures from an internal host. Examine EventCode 4625.

**Flag:** `NTLM`
```

```

---

***FLAG 35: DC Arrival and Credential Extraction***

**Objective:** The attacker reached the Domain Controller and immediately began working towards the AD database. Trace the first command and the extraction tool.

**Flag:** `whoami > vssadmin.exe`
```

```

---

***FLAG 36: Backdoor Account***

**Objective:** After extracting the database, the attacker created a new account designed to blend in with legitimate service accounts.

**Flag:** `svc_backup`
```

```

---

***FLAG 37: Backdoor Credentials***

**Objective:** The account creation command included the password as a command line argument. Terrible OPSEC, but captured permanently in your logs.

**Flag:** `P@ssw0rd123!`
```

```

---

***FLAG 38: Privilege Assignment***

**Objective:** Creating an account is not enough. The attacker ran a second command to give it elevated privileges.

**Flag:** `Domain Admins`
```

```

---

***FLAG 39: Exposed Credential***

**Objective:** The attacker needed to map a network drive on the DC to access tools. The drive mapping command included authentication credentials in plain text.

**Flag:** `EmberForge2024!`
```

```

---

***FLAG 40: Scheduled Task***

**Objective:** The attacker created a scheduled task to ensure their payload survives reboots. The name was chosen to look legitimate.

**Flag:** `WindowsUpdate`
```

```

---

***FLAG 41: Remote Access Tool***

**Objective:** A legitimate remote management application was silently installed for unattended access.

**Flag:** `AnyDesk`
```

```

---

***FLAG 42: Remote Access Configuration***

**Objective:** The attacker read and modified the remote access tool's configuration file. The commands reveal its full path.

**Flag:** `C:\ProgramData\AnyDesk\system.conf`
```

```

---

***FLAG 43: Anti-Forensics Tool***

**Objective:** The attacker used a built-in Windows utility to clear event logs on the DC. What tool was used?

**Flag:** `wevtutil`
```

```

---

***FLAG 44: Cleared Logs***

**Objective:** The attacker cleared more than one event log. Each clearing command targets a specific log by name. What two logs were cleared?

**Flag:** `Security, System`
```

```

---
