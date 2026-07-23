# Threat-Hunting-Scenario-EMBERFORGE-Source-Leak

## RDP Compromise Incident

**Report ID:** INC-2026-0404

**Analyst:** Nadezna Morris

**Date:** 04-April-2026

**Incident Date:** 10-Febuary-2026

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
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| take 10 
```
<img width="782" height="205" alt="image" src="https://github.com/user-attachments/assets/1be3f43b-be50-48e4-96ca-e25a45218f7e" />

---

***FLAG 1: Target Directory***

**Objective:** The attacker needed to package data before stealing it. The compression commands reveal exactly what they were targeting. What directory was the source of the stolen data?

**Flag:** `C:\GameDev`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("zip", "compress", "tar", "7z", "rar", "Compress-Archive", "ZipFile")
| project TimeGenerated,Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1196" height="82" alt="image" src="https://github.com/user-attachments/assets/84686c7d-5dfd-4ab0-bc12-7403cbe996c5" />

---

***FLAG 2: Exfil Destination***

**Objective:** The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details. What cloud provider received the data?

**Flag:** `mega`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("zip", "compress", "tar", "7z", "rar", "Compress-Archive", "ZipFile")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1246" height="115" alt="image" src="https://github.com/user-attachments/assets/0c51be52-a35a-4fa8-90e2-a32ab5345968" />

---

***FLAG 3: Attacker Attribution***

**Objective:** Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line. What email account was used to authenticate to the cloud service?

**Flag:** `jwilson.vhr@proton.me`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("rclone.conf", "rclone", "mega", "user", "pass")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="977" height="75" alt="image" src="https://github.com/user-attachments/assets/44e1e94f-cc5c-4628-93b1-17bb31b0fd7d" />

---

***FLAG 4: Domain Compromise Evidence***

**Objective:** This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file. This file contains every credential in the domain. What was it?

**Flag:** `ntds.dit`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("vssadmin", "shadow", "ntds", "vshadow", "wmic shadowcopy", "diskshadow")
| project TimeGenerated, CommandLine_s, TargetFilename_s
| order by TimeGenerated asc
```
<img width="1397" height="125" alt="image" src="https://github.com/user-attachments/assets/ca3f8062-b399-4651-81aa-d8bbdec3252c" />

---

***FLAG 5: Exfil Tool***

**Objective:** A cloud synchronisation tool was used to upload data externally. This tool is legitimate software commonly abused by threat actors. It was executed multiple times, not all successfully.

**Flag:** `rclone.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("onedrive", "dropbox", "gdrive", "rclone", "mega", "sync", "upload")
| project TimeGenerated, CommandLine_s
| order by TimeGenerated asc
```
<img width="896" height="76" alt="image" src="https://github.com/user-attachments/assets/a5993d95-4608-430d-ae67-d3a0c0b0756e" />

---

***FLAG 6: Exfil Destination IP***

**Objective:** The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3). What IP address received the stolen data?

**Flag:** `66.203.125.15`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "3"
| where CommandLine_s has_any ("rclone", "mega") or Image_s has "rclone"
| project TimeGenerated, Image_s, DestinationIp_s, DestinationPort_s, CommandLine_s
| order by TimeGenerated asc
```
<img width="806" height="70" alt="image" src="https://github.com/user-attachments/assets/4f552eac-3039-4e0e-9e3e-e978f6e72077" />

---

***FLAG 7: Attacker Credential Exposure***

**Objective:** The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution method exposed credentials far more recklessly than the others. Compare all executions and find the plaintext password.

**Flag:** `Summer2024!`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has "rclone"
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1327" height="115" alt="image" src="https://github.com/user-attachments/assets/a50f3292-2229-4674-898d-76652ac2dcf0" />

---

***FLAG 8: Archive Method***

**Objective:** Before exfiltration, the stolen data was compressed into an archive. The attacker used a built-in OS capability rather than third-party tools. This is a Living Off The Land technique. What cmdlet created the archive?

**Flag:** `Compress-Archive`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("zip", "compress", "tar", "7z", "rar", "Compress-Archive", "ZipFile")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1201" height="85" alt="image" src="https://github.com/user-attachments/assets/90dd932a-20b5-4599-ae7b-13cdcec733a5" />

---

***FLAG 9: Staging Server***

**Objective:** The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

**Flag:** `sync.cloud-endpoint.net`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("http", "https", "wget", "curl", "Invoke-WebRequest", "iwr", "DownloadFile", "certutil")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1140" height="80" alt="image" src="https://github.com/user-attachments/assets/073b88cf-e827-4806-bb74-62d727524342" />

---

***FLAG 10: Malicious File***

**Objective:** The incident started with Lisa opening something from her desktop. Find the earliest malicious process creation event on the workstation. A Windows utility was used to load a file that does not belong in a normal user workflow.

**Flag:** `review.dll`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("rundll32", "regsvr32", "mshta", "wscript", "cscript", "msiexec", "explorer")
| project TimeGenerated, Computer, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="987" height="72" alt="image" src="https://github.com/user-attachments/assets/383308c5-17ad-4af9-9367-36f3678b7964" />

---

***FLAG 11: Delivery Vector***

**Objective:** Look at the full path of the malicious file. The drive letter is significant. If the file is not on C:, consider how it got there. Mounted disk images (ISO, IMG, VHD) appear as virtual drives and bypass certain Windows security protections.

**Flag:** `D:`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("rundll32", "regsvr32", "mshta", "wscript", "cscript", "msiexec", "explorer")
| project TimeGenerated, Computer, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="987" height="72" alt="image" src="https://github.com/user-attachments/assets/383308c5-17ad-4af9-9367-36f3678b7964" />

---

***FLAG 12: Compromised User***

**Objective:** The User field in process creation events tells you which account executed the payload. This is patient zero.

**Flag:** `lmartin`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("rundll32", "regsvr32", "mshta", "wscript", "cscript", "msiexec", "explorer")
| project TimeGenerated, Computer, User_s, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="1216" height="80" alt="image" src="https://github.com/user-attachments/assets/0b6f4532-4041-4c02-bd86-2ba30f984f22" />

---

***FLAG 13: Execution Chain***

**Objective:** Every process has a parent, and that parent has a parent. Trace the full execution chain from the user action through to the malicious file being loaded.

**Flag:** `Explorer.EXE > rundll32.exe > review.dll`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("rundll32", "regsvr32", "mshta", "wscript", "cscript", "msiexec", "explorer")
| project TimeGenerated, Computer, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="987" height="72" alt="image" src="https://github.com/user-attachments/assets/383308c5-17ad-4af9-9367-36f3678b7964" />

---

***FLAG 14: Delivery Unpacking***

**Objective:** Before the malicious DLL was loaded, the user opened a downloaded archive. A compression tool extracted its contents to a folder in the user's profile. This extraction step came before the DLL execution.

**Flag:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("zip", "compress", "tar", "7z", "rar", "Compress-Archive", "ZipFile")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated desc
```
<img width="1230" height="82" alt="image" src="https://github.com/user-attachments/assets/ca17da2e-b1be-4b57-ae89-037fc11ffcaa" />

---

***FLAG 15: Dropped Payload***

**Objective:** Shortly after the initial DLL execution, a new executable appeared in a world-writable directory on the workstation. This became the attacker's primary tool for the rest of the operation.

**Flag:** `C:\Users\Public\update.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("C:\\Windows\\Temp", "C:\\Users\\Public", "C:\\ProgramData")
| where CommandLine_s has ".exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s, Image_s
| order by TimeGenerated asc
```
<img width="1217" height="80" alt="image" src="https://github.com/user-attachments/assets/85f36592-97c7-479f-bddb-5e47391b2e81" />

---

***FLAG 16: C2 Domain***

**Objective:** The malware needs to communicate with the attacker. Sysmon EventCode 22 captures every DNS query a process makes. The domain will look designed to blend in with legitimate cloud traffic.

**Flag:** `cdn.cloud-endpoint.net`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "22"
| where QueryName_s !has "microsoft" and QueryName_s !has "windows" and QueryName_s !has "google"
| project TimeGenerated, Computer, QueryName_s, Image_s
| order by TimeGenerated asc
```
<img width="837" height="77" alt="image" src="https://github.com/user-attachments/assets/11bfddb2-3ece-4770-a5e3-3fc94aa87a1c" />

---

***FLAG 17: Primary C2 IP***

**Objective:** DNS queries resolve domains to IP addresses. The QueryResults field inside the EventCode 22 raw XML contains the resolved IPs. You will need to parse Raw_s.

**Flag:** `104.21.30.237`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "22"
| where QueryName_s has "cloud-endpoint"
| extend ResolvedIP = extract(@"type:\s*5\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", 1, Raw_s)
| project TimeGenerated, QueryName_s, ResolvedIP, Raw_s
| order by TimeGenerated asc
```
<img width="1161" height="267" alt="image" src="https://github.com/user-attachments/assets/0fff6c18-0036-4d6d-be58-8cbc378075ce" />

---

***FLAG 18: Injection Chain***

**Objective:** The attacker injected code from one process into another to hide. Sysmon EventCode 8 (CreateRemoteThread) captures this. Trace the injection chain.

**Flag:** `rundll32.exe > notepad.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "8"
| extend SourceImage = extract(@"<Data Name='SourceImage'>(.*?)</Data>", 1, Raw_s)
| extend TargetImage = extract(@"<Data Name='TargetImage'>(.*?)</Data>", 1, Raw_s)
| project TimeGenerated, SourceImage, TargetImage
| order by TimeGenerated asc
```
<img width="897" height="72" alt="image" src="https://github.com/user-attachments/assets/35b6a138-d337-4c2b-9d72-b28deab6ab1d" />

---

***FLAG 19: UAC Bypass Binary***

**Objective:** Certain Windows executables are trusted to auto-elevate without a UAC prompt. Attackers hijack what these binaries execute via registry modifications. Look for registry changes (EventCode 13) followed immediately by a trusted binary execution.

**Flag:** `fodhelper.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where Image_s has "fodhelper"
   or CommandLine_s has "fodhelper"
| project TimeGenerated, Image_s, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="867" height="97" alt="image" src="https://github.com/user-attachments/assets/3650b3e0-7756-46df-ae47-ccff1e863742" />

---

***FLAG 20: Registry Bypass Enabler***

**Objective:** The UAC bypass works by creating a specific registry value that redirects execution. Two modifications were made in quick succession. One set the payload path. The other enables the hijack. What is that value name?

**Flag:** `DelegateExecute`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "13"
| where TargetObject_s has "ms-settings"
| project TimeGenerated, TargetObject_s, Image_s
| order by TimeGenerated asc
```
<img width="1275" height="82" alt="image" src="https://github.com/user-attachments/assets/ac7127fd-e48a-4e52-ac1c-b6a0f86b8c35" />

---

***FLAG 21: Stable Injection Chain***

**Objective:** After the UAC bypass, the elevated beacon performed a second injection for long-term stability. The source process was different from the first injection, and the target was running in a completely different security context.

**Flag:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "8"
| extend SourceImage = extract(@"<Data Name='SourceImage'>(.*?)</Data>", 1, Raw_s)
| extend TargetImage = extract(@"<Data Name='TargetImage'>(.*?)</Data>", 1, Raw_s)
| extend TargetUser = extract(@"<Data Name='TargetUser'>(.*?)</Data>", 1, Raw_s)
| project TimeGenerated, SourceImage, TargetImage, TargetUser
| order by TimeGenerated asc
```
<img width="802" height="70" alt="image" src="https://github.com/user-attachments/assets/63470a55-1162-4f14-83f3-b4dd47f7d97c" />

---

***FLAG 22: Credential Dumping Process***

**Objective:** LSASS holds credentials for every logged-in user. The attacker dumped its memory to disk. The dumping tool used direct syscalls to bypass API monitoring. You will NOT find ProcessAccess events (EventCode 10) for LSASS. What process created the dump file?

**Flag:** `update.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "11"
| where TargetFilename_s has_any ("lsass", ".dmp", "dump")
| project TimeGenerated, Computer, Image_s, TargetFilename_s
| order by TimeGenerated asc
```
<img width="851" height="97" alt="image" src="https://github.com/user-attachments/assets/6731820c-d4d4-48ca-b40d-8c83493fef6f" />

---

***FLAG 23: Dump Location***

**Objective:** You identified the process. Now find where it wrote the output. File creation events (EventCode 11) track every file written to disk. Where was the credential dump written?

**Flag:** `C:\Windows\System32\lsass.dmp`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "11"
| where Image_s has "spoolsv" or Image_s has "update"
| project TimeGenerated, Computer, Image_s, TargetFilename_s
| order by TimeGenerated asc
```
<img width="851" height="97" alt="image" src="https://github.com/user-attachments/assets/6731820c-d4d4-48ca-b40d-8c83493fef6f" />

---

***FLAG 24: User Enumeration***

**Objective:** The first command in the discovery sequence queries all user accounts in the domain.

**Flag:** `net user /domain`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("net user", "Get-ADUser", "dsquery user", "net group")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="566" height="75" alt="image" src="https://github.com/user-attachments/assets/a439dfbb-9be0-4382-a87d-dfc7d40cbbd7" />

---

***FLAG 25: Privilege Enumeration*** 

**Objective:** Immediately after listing users, the attacker queried a specific group to identify who has the highest level of access.
net group "Domain Admins" /domain

**Flag:** `net group "Domain Admins" /domain`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("net user", "Get-ADUser", "dsquery user", "net group")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated desc
```
<img width="718" height="70" alt="image" src="https://github.com/user-attachments/assets/a42da1a4-30f8-4814-a67f-fefaa86c912a" />

---

***FLAG 26: Infrastructure Mapping***

**Objective:** The final discovery command locates critical infrastructure. The attacker needs to know where to go next.

**Flag:** `nltest /dclist:emberforge.local`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("nltest", "domain controllers", "dclist", "net group \"Domain Controllers\"")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="620" height="70" alt="image" src="https://github.com/user-attachments/assets/49bc791f-f63b-4333-b382-50dfb35e1be5" />

---

***FLAG 27: Tool Staging Share***

**Objective:** Before moving laterally, the attacker set up the workstation as a distribution point. A network share was created.

**Flag:** `cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("net share", "New-SmbShare")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated desc 
```
<img width="840" height="73" alt="image" src="https://github.com/user-attachments/assets/b9a33ead-fe43-49c5-90f7-1284ef9773f7" />

---

***FLAG 28: Firewall Manipulation***

**Objective:** The workstation's firewall was blocking inbound connections needed for lateral movement. A rule was added. What name was given to the firewall rule?

**Flag:** `SMB`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("netsh", "firewall", "advfirewall", "New-NetFirewallRule")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1246" height="116" alt="image" src="https://github.com/user-attachments/assets/191904c9-8885-45d5-bb72-2696a4181fc3" />

---

***FLAG 29: Post-Escalation Parent***

**Objective:** After the beacon migrated to a SYSTEM process, all subsequent attacker commands on the workstation were executed as children of that process. Look at the parent process of the lateral movement commands (share creation, file copies, firewall changes).

**Flag:** `spoolsv.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("net share", "netsh", "copy")
| where CommandLine_s has "SMB"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="997" height="77" alt="image" src="https://github.com/user-attachments/assets/54b5c1ac-e4a6-43cc-a898-a6aa4a34accc" />

---

***FLAG 30: Beacon Distribution***

**Objective:** The attacker pushed their primary tool to the server via Windows admin shares (C$). What was the full command?

**Flag:** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("net share", "netsh", "copy")
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated desc
```
<img width="995" height="72" alt="image" src="https://github.com/user-attachments/assets/ab3b9038-aca4-414b-a19d-0788d5a3b514" />

---

***FLAG 31: LOLBin Tool Staging***

**Objective:** On the server, a built-in Windows utility was abused to download tools from the attacker's staging infrastructure. What utility was used, and what was the full URL it downloaded from?

**Flag:** `certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s has_any ("certutil", "bitsadmin", "wget", "curl", "Invoke-WebRequest", "iwr", "DownloadFile")
| where CommandLine_s has "http"
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1141" height="81" alt="image" src="https://github.com/user-attachments/assets/6b0300b0-c3f0-4d3a-8777-309ce0db08da" />

---

***FLAG 32: Remote Execution Evidence***

**Objective:** Now look at the server. The attacker used a remote execution technique that creates temporary Windows services with random names. These appear in EventCode 7045 in Raw_s.

**Flag:** `MzLblBFm`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventID_s == "13"
| where TargetObject_s has "Services"
| project TimeGenerated, Computer, TargetObject_s, Details_s
| order by TimeGenerated desc
````
<img width="988" height="72" alt="image" src="https://github.com/user-attachments/assets/c6047a21-d892-48a2-913e-a667235c6f34" />

---

***FLAG 33: First Command on Server***

**Objective:** The remote execution technique redirects command output to temporary files. The very first attacker command on any newly compromised host is almost always the same.

**Flag:** `whoami`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Raw_s has_any ("__output")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="1207" height="80" alt="image" src="https://github.com/user-attachments/assets/a114b07b-53a6-4342-895f-e88a09f232b4" />

---

***FLAG 34: Failed Lateral Movement***

**Objective:** The attacker's first lateral movement method was unreliable. Authentication logs on the server show repeated failures from an internal host. Examine EventCode 4625.

**Flag:** `NTLM`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Raw_s has "NTLM" or Raw_s has "Kerberos"
| project TimeGenerated, Computer, Raw_s
| sort by TimeGenerated asc 
```
<img width="1922" height="222" alt="image" src="https://github.com/user-attachments/assets/dabda001-7871-4e27-a742-a5f4eec1f734" />

---

***FLAG 35: DC Arrival and Credential Extraction***

**Objective:** The attacker reached the Domain Controller and immediately began working towards the AD database. Trace the first command and the extraction tool.

**Flag:** `whoami > vssadmin.exe`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="1027" height="98" alt="image" src="https://github.com/user-attachments/assets/e88656f3-2383-4e96-bfbe-6e01dbd39749" />

---

***FLAG 36: Backdoor Account***

**Objective:** After extracting the database, the attacker created a new account designed to blend in with legitimate service accounts.

**Flag:** `svc_backup`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="907" height="72" alt="image" src="https://github.com/user-attachments/assets/52d261f4-52e0-498a-a73c-d7ee4c594da1" />

---

***FLAG 37: Backdoor Credentials***

**Objective:** The account creation command included the password as a command line argument. Terrible OPSEC, but captured permanently in your logs.

**Flag:** `P@ssw0rd123!`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="907" height="72" alt="image" src="https://github.com/user-attachments/assets/52d261f4-52e0-498a-a73c-d7ee4c594da1" />

---

***FLAG 38: Privilege Assignment***

**Objective:** Creating an account is not enough. The attacker ran a second command to give it elevated privileges.

**Flag:** `Domain Admins`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="1180" height="85" alt="image" src="https://github.com/user-attachments/assets/0fa7db66-ea1f-4ad7-8490-6e45ab38b185" />

---

***FLAG 39: Exposed Credential***

**Objective:** The attacker needed to map a network drive on the DC to access tools. The drive mapping command included authentication credentials in plain text.

**Flag:** `EmberForge2024!`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="1162" height="86" alt="image" src="https://github.com/user-attachments/assets/2e0e3229-dd2e-42a7-9e7a-dffea0cc0b27" />

---

***FLAG 40: Scheduled Task***

**Objective:** The attacker created a scheduled task to ensure their payload survives reboots. The name was chosen to look legitimate.

**Flag:** `WindowsUpdate`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where CommandLine_s has_any ("schtasks", "New-ScheduledTask", "Register-ScheduledTask")
| project TimeGenerated, CommandLine_s
| order by TimeGenerated asc
```
<img width="1166" height="80" alt="image" src="https://github.com/user-attachments/assets/a6802ee3-9e5e-42dd-be33-13c2f999267c" />

---

***FLAG 41: Remote Access Tool***

**Objective:** A legitimate remote management application was silently installed for unattended access.

**Flag:** `AnyDesk`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where CommandLine_s has_any ("anydesk", "teamviewer", "screenconnect", "logmein", "radmin", "vnc")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="682" height="71" alt="image" src="https://github.com/user-attachments/assets/3bccd3e2-bd70-48dc-ac8d-be733cf233b7" />

---

***FLAG 42: Remote Access Configuration***

**Objective:** The attacker read and modified the remote access tool's configuration file. The commands reveal its full path.

**Flag:** `C:\ProgramData\AnyDesk\system.conf`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where CommandLine_s has_any ("anydesk", "teamviewer", "screenconnect", "logmein", "radmin", "vnc")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```
<img width="781" height="71" alt="image" src="https://github.com/user-attachments/assets/9c795f4f-84ed-440a-89d5-75eb944f883e" />

---

***FLAG 43: Anti-Forensics Tool***

**Objective:** The attacker used a built-in Windows utility to clear event logs on the DC. What tool was used?

**Flag:** `wevtutil`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="1197" height="115" alt="image" src="https://github.com/user-attachments/assets/f81c79ce-8de3-4a96-a0fb-2e6a773ee7dc" />

---

***FLAG 44: Cleared Logs***

**Objective:** The attacker cleared more than one event log. Each clearing command targets a specific log by name. What two logs were cleared?

**Flag:** `Security, System`
```
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-02-01 00:00))
| where Computer has "EC2AMAZ-EEU3IA2"
| where EventID_s == "1"
| where CommandLine_s !has "Splunk" and CommandLine_s !has "svchost" and CommandLine_s !has "WmiPrvSE" and CommandLine_s !has "taskhostw.exe"
| project TimeGenerated, CommandLine_s, ParentCommandLine_s
| order by TimeGenerated asc
```
<img width="1197" height="115" alt="image" src="https://github.com/user-attachments/assets/f81c79ce-8de3-4a96-a0fb-2e6a773ee7dc" />

---


---

**Status:** Complete

**Next Review:** 11-April-2026

**Distributed by:** Cyber Range
